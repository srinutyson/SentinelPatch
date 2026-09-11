import {z} from 'zod';
import fs from 'fs';
import path from 'path';
import { checkReachability } from './reachability.js';
import { getFunctionNameAtLocation , extractAdvisoryFunctionNames } from './functionMatch.js';

const locationSchema = z.object({
      funcId : z.number(),
      file : z.string(),
      startLine : z.number(),
      startCol : z.number(),
      endLine :  z.number(),
      endCol : z.number()
});

export const findingSchema = z.object({
      cveId : z.string(),
      packageName : z.string(),
      packageVersion : z.string(),
      repoName : z.string(),
      entryPointFile : z.string(),
      path : z.array(z.number()),
      locations : z.array(locationSchema),
      advisorySummary : z.string(),
      advisoryDetails : z.string(),
      functionLevelMatch : z.boolean(),
});

export const VerdictSchema = z.object({
       cveId : z.string(),
       verdict : z.enum(['exploitable' , 'not-exploitable' , 'insufficient-evidence']),
       confidence : z.number().min(0).max(1),
       reasoning : z.string(),
       citedEvidence : z.array(z.object(
        {
            file : z.string(),
            line : z.number(),
            note : z.string(),
        }
       )),
})

export function buildFinding(ctx , vuln , packageName , packageVersion , callGraphPath , reachabilityResult){
      if(!reachabilityResult.reachable || !reachabilityResult.path){
        throw new Error(
            `buildFinding requires a reachable result with a real path — got reachable=${reachabilityResult.reachable}. ` +
            `Check reachabilityResult.reachable before calling this.`
        );
      }

      const callGraph = JSON.parse(fs.readFileSync(callGraphPath , 'utf8'));
      const locations = reachabilityResult.path.map((funcId)=>{
               const locationString = callGraph.functions[funcId];
               const [fileIdxStr , startLine , startCol , endLine , endCol] = locationString.split(':');
               const fileIdx = Number(fileIdxStr);

               return {
                   funcId,
                   file : callGraph.files[fileIdx],
                   startLine : Number(startLine),
                   startCol : Number(startCol),
                   endLine : Number(endLine),
                   endCol : Number(endCol),
               };
      });
      const terminalLocation = locations[locations.length - 1];
      const terminalFilePath = path.join(ctx.repoPath , terminalLocation.file);
      const terminalFunctionName = getFunctionNameAtLocation(terminalFilePath , terminalLocation.startLine);
      const advisoryFunctionNames = extractAdvisoryFunctionNames(vuln.summary , vuln.details);
      const functionLevelMatch = terminalFunctionName !== null && advisoryFunctionNames.has(terminalFunctionName);

      const finding = {
           cveId : vuln.id,
           packageName,
           packageVersion,
           repoName : path.basename(ctx.repoPath),
           entryPointFile : path.basename(callGraphPath , '.json'),
           path : reachabilityResult.path,
           locations,
           advisorySummary : vuln.summary,
           advisoryDetails : vuln.details,
           functionLevelMatch,
      };

      return findingSchema.parse(finding);
}

function loadVulnerabilityReport(ctx){
      if(!fs.existsSync(ctx.vulnerabilitiesPath)){
        console.warn(`No vulnerability report found at ${ctx.vulnerabilitiesPath} — run the vulnerability query step first.`);
        return [];
      }
      return  JSON.parse(fs.readFileSync(ctx.vulnerabilitiesPath , 'utf-8'));
}

function getCallGraphFilesForRepo(ctx){
    if(!fs.existsSync(ctx.callGraphsDir)){
        return [];
    }
    return  fs.readdirSync(ctx.callGraphsDir)
            .filter((filename)=> filename.endsWith('.json'))
            .map((filename)=> path.join(ctx.callGraphsDir , filename));
}

export function generateFindings(ctx){
         const vulnerabilities = loadVulnerabilityReport(ctx).filter((entry)=> entry.vulnerabilities && entry.vulnerabilities.length > 0);
         const callGraphPaths = getCallGraphFilesForRepo(ctx);

         console.log(`Checking ${vulnerabilities.length} vulnerable package(s) against ${callGraphPaths.length} call graph(s) for ${ctx.projectId}...`);

         const findings = [];

        for(const dep of vulnerabilities){
            const reachableResults = [];

            for(const callGraphPath of callGraphPaths){
                const result = checkReachability(callGraphPath , dep.name , dep.version , ctx);

                if(result.status === 'reachable'){
                    reachableResults.push({ callGraphPath, result });
                } else if(result.status === 'inconclusive'){
                    console.log(`  ⚠️  inconclusive: ${dep.name} from ${path.basename(callGraphPath)} — static analysis coverage was incomplete, reachability could not be determined`);
                }
            }

            if(reachableResults.length > 0){
                const entryPoints = reachableResults.map(({ callGraphPath }) => path.basename(callGraphPath , '.json'));
                console.log(`  ✅ reachable: ${dep.name} (proven from: ${entryPoints.join(', ')})`);

                const { callGraphPath, result } = reachableResults[0];

                for(const vuln of dep.vulnerabilities){
                    const finding = buildFinding(ctx , vuln , dep.name , dep.version , callGraphPath , result);
                    findings.push(finding);
                }
            }
        }
    console.log(`Done. ${findings.length} finding(s) generated.`);
    return findings;
}

export function generateUnresolvedFindings(ctx){
         const vulnerabilities = loadVulnerabilityReport(ctx).filter((entry)=> entry.vulnerabilities && entry.vulnerabilities.length > 0);
         const callGraphPaths = getCallGraphFilesForRepo(ctx);

         const unresolved = [];

        for(const dep of vulnerabilities){
            const inconclusiveEntryPoints = [];

            for(const callGraphPath of callGraphPaths){
                const result = checkReachability(callGraphPath , dep.name , dep.version , ctx);

                if(result.status === 'inconclusive'){
                    inconclusiveEntryPoints.push(path.basename(callGraphPath , '.json'));
                }
            }

            if(inconclusiveEntryPoints.length > 0){
                for(const vuln of dep.vulnerabilities){
                    unresolved.push({
                        cveId: vuln.id,
                        packageName: dep.name,
                        packageVersion: dep.version,
                        repoName: path.basename(ctx.repoPath),
                        entryPointFiles: inconclusiveEntryPoints,
                        status: 'inconclusive',
                        advisorySummary: vuln.summary,
                        reason: 'Static analysis coverage was incomplete for this repo (one or more entry points failed to analyze) — reachability could not be confidently determined.',
                    });
                }
            }
        }
    return unresolved;
}
