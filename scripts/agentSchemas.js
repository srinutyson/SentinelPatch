import {z} from 'zod';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { checkReachability } from './reachability.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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
});

export function buildFinding(repoName , vuln , packageName , packageVersion , callGraphPath , reachabilityResult){
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


      const finding = {
           cveId : vuln.id,
           packageName,
           packageVersion,
           repoName,
           entryPointFile : path.basename(callGraphPath , '.json'),
           path : reachabilityResult.path,
           locations,
           advisorySummary : vuln.summary,
           advisoryDetails : vuln.details,
      };

      return findingSchema.parse(finding);
}

function loadVulnerabilityReport(repoName){
     
      const reportPath = path.join(__dirname , '..' , `vulnerabilities-${repoName}.json`);
      if(!fs.existsSync(reportPath)){
        console.warn(`No vulnerability report found at ${reportPath} — run: node scripts/queryVulnerabilities.js ${repoName}`);
        return [];
      }
      return  JSON.parse(fs.readFileSync(reportPath , 'utf-8'));

}

function getCallGraphFilesForRepo(repoName){
    const dirPath = path.join(__dirname , '..' , 'callgraphs');
    return  fs.readdirSync(dirPath)
            .filter((filename)=> filename.startsWith(`${repoName}__`) && filename.endsWith('.json'))
            .map((filename)=> path.join(dirPath , filename));
} 

export function generateFindings(repoName){
         const vulnerabilities = loadVulnerabilityReport(repoName).filter((entry)=> entry.vulnerabilities && entry.vulnerabilities.length > 0);
         
         const callGraphPaths =getCallGraphFilesForRepo(repoName);
         
         console.log(`Checking ${vulnerabilities.length} vulnerable package(s) against ${callGraphPaths.length} call graph(s) for ${repoName}...`);
         
         const findings = [];
         
        for(const callGraphPath of callGraphPaths){
            for(const dep of vulnerabilities){
                const result = checkReachability(callGraphPath,dep.name);
                
                if(result.reachable){
                    console.log(`  ✅ reachable: ${dep.name} from ${path.basename(callGraphPath)}`);
                    for(const vuln of dep.vulnerabilities){
                        const finding = buildFinding(repoName , vuln , dep.name , dep.version , callGraphPath , result);
                         findings.push(finding);
                    }
                }
            }
        }
    console.log(`Done. ${findings.length} finding(s) generated.`);
    return findings;
}