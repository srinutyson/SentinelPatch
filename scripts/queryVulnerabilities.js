import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getDependencies } from "./extractDependencies.js";



// async function queryOSV(name , version){
//       try{

//           const response =  await fetch('https://api.osv.dev/v1/query' , {
//          method : 'POST',
//        headers :  {"Content-Type" : "application/json"},
//          body : JSON.stringify({
//                 package : {
//                      name : name,
//                      ecosystem : 'npm'
//                 },
//                 version : version,
//          }),
//       });
//          if(!response.ok){
//              console.error(`OSV query failed for ${name}@${version}:  HTTP ${response.status}`);
//              return [];
//          }

//          const data =  await response.json()
//          return data.vulns || [];
//       }catch(error){
//            console.error(`OSV query error for ${name}@${version}:`, error.message);
//            return [];
//       }

    
// }

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
    const queryable = dependencies.filter((dep) => dep.version);
    const skipped = dependencies.filter((dep) => !dep.version);

    for (const dep of skipped) {
        console.warn(`Skipping ${dep.name} : no resolved version found `);
    }

    const vulnListsByIndex = await queryOSVBatch(queryable);
    
    const uniqueIds = new Set();
    for (const vulnList of vulnListsByIndex) {
        for (const v of vulnList) {
            uniqueIds.add(v.id);
        }
    }

    const detailsCache = new Map();
    for (const id of uniqueIds) {
        const full = await getVulnDetails(id);
        if (full) {
            detailsCache.set(id, simplifyvulns(full));
        }
    }
    
    const results = queryable.map((dep, i) => {
        const idsForThisDep = vulnListsByIndex[i].map((v) => v.id);
        const vulnerabilities = idsForThisDep
            .map((id) => detailsCache.get(id))
            .filter((v) => v !== undefined);

        return {
            name: dep.name,
            version: dep.version,
            vulnerabilities,
        };
    });

    return results;
}
export async function queryOSVBatch(dependencies){
       const queryable = dependencies.filter((dep)=>dep.version);
       const queries = queryable.map((dep)=>({
          package : { name : dep.name , ecosystem : 'npm'},
          version : dep.version,
       }));
    try{
         const response  = await fetch('https://api.osv.dev/v1/querybatch' , {
             method : 'POST',
             headers : {"Content-Type" : "application/json"},
             body : JSON.stringify({queries})
         });
         if(!response.ok){
             console.error(`OSV batch query failed: HTTP ${response.status}`);
             return queryable.map(() => []);
         }
         const data = await response.json();
         return data.results.map((r)=>
              r.vulns || []
         );
    }
    catch(error){
         console.error(`OSV batch query error:`, error.message);
        return queryable.map(() => []);
    }
}

async function getVulnDetails(id){
        try{
            const response = await fetch(`https://api.osv.dev/v1/vulns/${id}`);

        if (!response.ok) {
            console.error(`Failed to fetch details for ${id}: HTTP ${response.status}`);
            return null;
        }

        return await response.json();
        }
        catch(error){
             console.error(`Error fetching details for ${id}:`, error.message);
             return null;  
        }
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