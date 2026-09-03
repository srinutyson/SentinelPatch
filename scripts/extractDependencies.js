import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url';

const dirname = path.dirname(fileURLToPath(import.meta.url));

export function getDependencies(reponame){
        const repoPath = path.join(dirname , '..' , 'target-repos' , reponame);

        const pkgJsonPath  = path.join(repoPath , "package.json");
        const lockJsonPath = path.join(repoPath, "package-lock.json");

        const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath , "utf8"));

        const lockJson = JSON.parse(fs.readFileSync(lockJsonPath , "utf8"));

        const directDependencies = new Set(Object.keys(pkgJson.dependencies || {}));

      
        if(lockJson.lockfileVersion >= 2){
               return dedupe(getAllInstalledPackages(lockJson , directDependencies));
        }
           
        return dedupe(walkV1Tree(lockJson.dependencies,directDependencies));
       

        
}

 function getAllInstalledPackages(lockJson,dirNames){
       const entries = Object.entries(lockJson.packages);
     return  entries.filter(([key])=> key !== "").map(([key,entry])=>{
             const lastIdx = key.lastIndexOf("node_modules/");
             const firstIdx = key.indexOf("node_modules/");
             const isTopLevel = lastIdx === firstIdx;
             const name = key.slice(lastIdx + "node_modules/".length);
             return {
                   name ,
                   version : entry.version || null,
                   direct : isTopLevel && dirNames.has(name),

             };
       });

}

function walkV1Tree(depsObject , directNames , isToplevel = true){
         const results = [];
         const entries = Object.entries(depsObject || {});

         for(const [name , info] of entries){
               results.push({
                 name,
                 version : info.version || null , 
                 direct : isToplevel && directNames.has(name),
               });
                if (info.dependencies) {
                results.push(...walkV1Tree(info.dependencies, directNames, false));
            }
         }
         return results;
}

function dedupe(packages){
    const seen = new Set();
    const results = [];

    for(const pkg of packages){
        const key = `${pkg.name}@${pkg.version}`;
        if(seen.has(key))continue;
        seen.add(key);
        results.push(pkg);
    }
    return results;
}