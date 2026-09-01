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

        const directDependencies = Object.keys(pkgJson.dependencies || {});

        function resolveVersion(name){
            if(lockJson.lockfileVersion >= 2){
                const entry = lockJson.packages?.[`node_modules/${name}`];
                return entry?.version || null;
            }
            else {
               const entry = lockJson.dependencies?.[name];
                return entry?.version || null;
            }
        }

        return directDependencies.map((name) =>({
            name , 
            version: resolveVersion(name)
        }));
        
}