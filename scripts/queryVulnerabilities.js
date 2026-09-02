import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getDependencies } from "./extractDependencies.js";



async function queryOSV(name , version){
      try{

          const response =  await fetch('https://api.osv.dev/v1/query' , {
         method : 'POST',
       headers :  {"Content-Type" : "application/json"},
         body : JSON.stringify({
                package : {
                     name : name,
                     ecosystem : 'npm'
                },
                version : version,
         }),
      });
         if(!response.ok){
             console.error(`OSV query failed for ${name}@${version}:  HTTP ${response.status}`);
             return [];
         }

         const data =  await response.json()
         return data.vulns || [];
      }catch(error){
           console.error(`OSV query error for ${name}@${version}:`, error.message);
           return [];
      }

    
}

function simplifyvulns(vuln){
      return {
         id : vuln.id,
         summary : vuln.summary || null,
         details : vuln.details || null,
         affected : vuln.affected || [],
         references : vuln.references || [],
      };
}

export async function checkDependencies(reponame){
    const dependencies = getDependencies(reponame);
    const results = [];

    for(const dep of dependencies){
         if(!dep.version){
             console.warn(`Skipping ${dep.name} : no resolved version found `);
             continue;
         }

         const vulns = await queryOSV(dep.name , dep.version);
         results.push({
             name : dep.name,
             version : dep.version,
             vulnerabilities : vulns.map(simplifyvulns)
         });

        
    }
     return results;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function writeVulnerabilityReport(reponame){
      const results = await checkDependencies(reponame);
      const outPath = path.join(__dirname , '..' , `vulnerabilities-${reponame}.json`);
      fs.writeFileSync(outPath , JSON.stringify(results , null , 2));
       console.log(`Wrote vulnerability report for ${reponame} to ${outPath}`);
       return results;
}


const reponame = process.argv[2] || 'hackathon-starter';
await writeVulnerabilityReport(reponame);