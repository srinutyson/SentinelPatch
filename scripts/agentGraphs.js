import 'dotenv/config';
import { GoogleGenAI } from '@google/genai';
import { generateFindings , VerdictSchema } from './agentSchemas.js';
import { readFunctionBody , readSourceLines , readFunctionBodyDeclaration , readSourceLinesDeclaration } from './agentTools.js';


const ai = new GoogleGenAI({apiKey : process.env.GEMINI_API_KEY });



const SYSTEM_INSTRUCTION = `
    You are a security analyst investigating whether a proven static call path from a vulnerable dependency is actually exploitable in this application.

    You will be given a "finding": a CVE, the vulnerable package, and a real call path (proven by static analysis) from an app entry point into that package's code, including file and line locations for each step, plus the advisory's own description of the vulnerability.

    Investigate three things using the tools available to you:
    1. Does attacker-controlled data actually flow along this path into the vulnerable code, or is it only ever fed safe, hardcoded values?
    2. Is there a guard anywhere on the path (an auth check, input sanitization) that would stop a real attacker even though the path technically exists?
    3. Is this path reachable from a real production entry point, or does it only ever get triggered by test code?
    
    You will also see a "functionLevelmatch" field on the finding. If it is false, static analysis could only confirm the app reaches the vulnerable package generally — not the specific function this advisory names as vulnerable. Treat "functionLevelmatch: false" as a strong signal toward "insufficient-evidence" unless your own reading of the source independently proves the vulnerable code path is actually reached.
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
                model : 'gemini-3.7-flash',
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


const testFindings = generateFindings('vuln-fixture');
const testFinding = testFindings[0];


callGeminiOnce(buildInitialContents(testFinding)).then((response)=>{
      console.log(JSON.stringify(response, null, 2));
});