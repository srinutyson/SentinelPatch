import 'dotenv/config';
import { GoogleGenAI } from '@google/genai';
import { generateFindings , VerdictSchema } from './agentSchemas.js';
import { readFunctionBody , readSourceLines , readFunctionBodyDeclaration , readSourceLinesDeclaration } from './agentTools.js';
import { Annotation, START, StateGraph , END } from '@langchain/langgraph';


const ai = new GoogleGenAI({apiKey : process.env.GEMINI_API_KEY });

const MAX_STEPS = 8;

const SYSTEM_INSTRUCTION = `
    You are a security analyst investigating whether a proven static call path from a vulnerable dependency is actually exploitable in this application.

    You will be given a "finding": a CVE, the vulnerable package, and a real call path (proven by static analysis) from an app entry point into that package's code, including file and line locations for each step, plus the advisory's own description of the vulnerability.

    Investigate three things using the tools available to you:
    1. Does attacker-controlled data actually flow along this path into the vulnerable code, or is it only ever fed safe, hardcoded values?
    2. Is there a guard anywhere on the path (an auth check, input sanitization) that would stop a real attacker even though the path technically exists?
    3. Is this path reachable from a real production entry point, or does it only ever get triggered by test code?

    You will also see a "functionLevelMatch" field. If it is false, static analysis could only confirm the app reaches the vulnerable package generally — not the specific function this advisory names as vulnerable. Treat "functionLevelMatch: false" as a strong signal toward "insufficient-evidence" unless your own reading of the source independently proves the vulnerable code path is actually reached.
    Do not attempt to search the rest of the vulnerable package's source for the advisory's named function if it is not the one at the proven path's final location — your tools can only read a specific line range you already know, not search by name, so this kind of exploration will not converge. If "functionLevelMatch" is false, a brief check of the path's actual terminal location (to confirm it's unrelated to the advisory's named function) is enough basis to conclude "insufficient-evidence" directly, rather than continuing to search elsewhere in the file.
    You can call readSourceLines or readFunctionBody as many times as needed to inspect the actual code at any point along the path before deciding.

    When you are confident in your answer, respond with ONLY a JSON object (no other text) in exactly this shape:
    {
    "cveId": string,
    "verdict": "exploitable" | "not-exploitable" | "insufficient-evidence",
    "confidence": number between 0 and 1,
    "reasoning": string explaining your conclusion,
    "citedEvidence": [ { "file": string, "line": number, "note": string }, ... ]
    }
    `;

function stripCodeFences(text) {
    const trimmed = text.trim();
    const fenceMatch = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
    return fenceMatch ? fenceMatch[1] : trimmed;
}

function buildInitialContents(finding){
        return [
              {
                 role : 'user',
                 parts : [
                         {text : SYSTEM_INSTRUCTION},
                         {text : `Here is the finding to investigate:\n${JSON.stringify(finding, null, 2)}`},
                 ],
              },
        ];
}

async function callGeminiOnce(contents){
          const response = await ai.models.generateContent({
                model : 'gemini-3.6-flash',
                contents,
                config : {
                     tools : [
                         {
                             functionDeclarations : [readSourceLinesDeclaration , readFunctionBodyDeclaration],
                         },
                     ],
                },
          });

          return response ; 
}

function insufficientEvidenceVerdict(cveId , reasoning){
     return {
          cveId , 
          verdict : 'insufficient-evidence',
          confidence : 0,
          reasoning ,
          citedEvidence : [],
     }
}

const AgentState = Annotation.Root({
    finding : Annotation(),
    contents : Annotation({
         reducer : (state , update) =>state.concat(update),
         default : () => [],
    }),
    stepCount : Annotation({
          reducer : (_state , update) => update,
          default : ()=> 0,
    }),
    verdict : Annotation({
        default : () => null,
    }),
})

async function callModelNode(state){
      const response = await callGeminiOnce(state.contents);
      const modelContent = response.candidates[0].content;
      return{
          contents : [modelContent],
          stepCount : state.stepCount+1,
      };
}

function getFunctionCallPart(state){
     const lastContent = state.contents[state.contents.length - 1];
     return lastContent.parts.find((part)=> part.functionCall);
}

function routeAfterModel(state){
      const functionCallPart = getFunctionCallPart(state);

      if(functionCallPart && state.stepCount >= MAX_STEPS){
          return 'capReached';
      }
      if(functionCallPart){
         return 'hasFunctionCall';
      }
      return 'finalAnswer';
}

function executeToolNode(state){
     const functionCallPart = getFunctionCallPart(state);

     const {name ,  args , id} = functionCallPart.functionCall;
     console.log(`  Step tool call: ${name}(${JSON.stringify(args)})`);
     const repoName = state.finding.repoName;

     let result ;
     if(name === 'readSourceLines'){
          result = readSourceLines(repoName , args.filePath , args.startLine , args.endLine,args.contextLines); 
     }
     else if(name === 'readFunctionBody'){
         result = readFunctionBody(repoName , {
             file : args.file,
             startLine : args.startLine,
             endLine : args.endLine,
         });
     }
     else {
         result = `Unknown tool requested: ${name}`;
     }

     return {
         contents : [
            {
                 role: 'user',
                 parts : [
                     {
                        functionResponse :{
                            name , 
                            response : {result},
                            id,
                        }
                     },
                 ],
            },
         ],
     };
}

function finalVerdictNode(state){
     const lastContent = state.contents[state.contents.length-1];
     const textPart = lastContent.parts.find((part)=> part.text);

     if(!textPart){
         return {
            verdict : insufficientEvidenceVerdict(
                state.finding.cveId,
                 'Agent\'s final turn contained no text to parse as a verdict.'
            ),
         };

     }

     let parsedJson ;
       try{
          parsedJson = JSON.parse(stripCodeFences(textPart.text));
       }catch(error){
           return {
              verdict : insufficientEvidenceVerdict(
                   state.finding.cveId,
                `Agent's final response was not valid JSON: ${error.message}`
              ),
           };
       }

      const result = VerdictSchema.safeParse(parsedJson);
      if (!result.success) {
        return {
            verdict: insufficientEvidenceVerdict(
                state.finding.cveId,
                `Agent's final JSON failed schema validation: ${JSON.stringify(result.error.issues)}`
            ),
        };
    }
    
    return {verdict : result.data};

}

function forceInsufficientEvidenceNode(state){
       return {
          verdict : insufficientEvidenceVerdict(
             state.finding.cveId,
             `Reached the max step limit (${MAX_STEPS}) while the agent still wanted to investigate further.`
          )
       };
}

const graph = new StateGraph(AgentState)
               .addNode('callModel' , callModelNode)
               .addNode('executeTool' , executeToolNode)
               .addNode('finalizeVerdict' , finalVerdictNode)
               .addNode('forceInsufficientEvidence' , forceInsufficientEvidenceNode)
               .addEdge(START , 'callModel')
               .addConditionalEdges('callModel' , routeAfterModel , {
                 hasFunctionCall : 'executeTool',
                 capReached : 'forceInsufficientEvidence',
                 finalAnswer : 'finalizeVerdict',
               })
               .addEdge('executeTool' , 'callModel')
               .addEdge('finalizeVerdict',END)
               .addEdge('forceInsufficientEvidence' , END);

const compiledGraph = graph.compile();

export async function runFindingThroughAgent(finding){
      const finalState = await compiledGraph.invoke(
           {
            finding,
            contents : buildInitialContents(finding),
            stepCount : 0,
            verdict : null,
           },
           {recursionLimit : 25}
      );

      return finalState.verdict;
}




const testFindings = generateFindings('vuln-fixture');
const testFinding = testFindings.find((f) => f.cveId === 'GHSA-29mw-wpgm-hmr9');

runFindingThroughAgent(testFinding).then((verdict) => {
    console.log(JSON.stringify(verdict, null, 2));
});