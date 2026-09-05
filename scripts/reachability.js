import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';


const __dirname = path.dirname(fileURLToPath(import.meta.url));

function getInstalledVersionAtPath(absoluteFilePath, packageName){
    const marker = `node_modules/${packageName}/`;
    const markerIndex = absoluteFilePath.lastIndexOf(marker);
    if(markerIndex === -1) return null;

    const packageRoot = absoluteFilePath.slice(0, markerIndex + marker.length);
    const packageJsonPath = path.join(packageRoot, 'package.json');

    try {
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        return packageJson.version || null;
    } catch (error) {
        console.warn(`Could not read installed version at ${packageJsonPath}: ${error.message}`);
        return null;
    }
}

export function getVulnerablePackageFileIndices(callGraph , packageName,expectedVersion , repoRootDir){
     const indices = new Set();
       callGraph.files.forEach((filePath , index)=>{
           if(filePath.includes(`node_modules/${packageName}/`)){
              const absoluteFilePath = path.join(repoRootDir , filePath);
              const installedVersion = getInstalledVersionAtPath(absoluteFilePath , packageName);

              if(installedVersion === expectedVersion){
                  indices.add(index);
              } else if(installedVersion === null){
                  console.warn(`Could not determine installed version for ${filePath} — excluding from vulnerable set to avoid an unverified match`);
              } else {
                  console.log(`  Skipping ${filePath} — installed version ${installedVersion} does not match known-vulnerable version ${expectedVersion}`);
              }
          }
       });

       return indices;

       
}

export function getFunctionsInFiles(callGraph , fileIndices){
    const matchedFuncIds = new Set();
     const entries =  Object.entries(callGraph.functions);
     for(const [funcId ,locationString] of entries){
        const [fileIndxStr] = locationString.split(':');
        const fileIdx = Number(fileIndxStr);

        if(fileIndices.has(fileIdx)){
             matchedFuncIds.add(Number(funcId));
        }

     }
     return matchedFuncIds;
     
}

export function getFileIndicesForPaths(callGraph, paths){
      const pathsSet = new Set(paths);
       const result = new Set();

       callGraph.files.forEach((filePath , index)=>{
           if(pathsSet.has(filePath)){
             result.add(index);
           }
       })
       return result;
}

export function buildAdjacencyMap(fun2fun){
        const adjacencyMap = new Map();
        for(const [caller , callee] of fun2fun){
            if(!adjacencyMap.has(caller)){
                adjacencyMap.set(caller , []);
            }
            adjacencyMap.get(caller).push(callee);
        }
        return adjacencyMap;
}

export function isReachable(startFuncIds , targetFuncIds , adjacencyMap){
       const queue = [...startFuncIds];
     
       const visited = new Set(startFuncIds);

       while(queue.length > 0){
            const current = queue.shift();
            if(targetFuncIds.has(current)) return true;
            const callees = adjacencyMap.get(current) || [];
            for(const callee of callees){
                 if(visited.has(callee))continue;
                 visited.add(callee);
                 queue.push(callee);
            }

       }
       return false;
}

export function pathReconstruction(targetFuncId,parentMap){
      const path = [targetFuncId];
      let node = targetFuncId;
      while(parentMap.has(node)){
         node = parentMap.get(node);
         path.push(node);
      }
      return path.reverse();
}

export function findReachablePath(startFuncIds , targetFuncIds , adjacencyMap){

        const queue = [...startFuncIds];
        const visited = new Set(startFuncIds);
        const parentMap = new Map();
        while(queue.length > 0){
            const current = queue.shift();
            if(targetFuncIds.has(current)) {
               return pathReconstruction(current , parentMap);
               
            }
            const callees = adjacencyMap.get(current) || [];
            for(const callee of callees){
                 if(visited.has(callee))continue;
                 visited.add(callee);
                 queue.push(callee);
                 parentMap.set(callee , current);
            }

       }
       return null;

}
const callGraphCache = new Map();

function loadCallGraphData(callGraphPath){
    if(callGraphCache.has(callGraphPath)){
        return callGraphCache.get(callGraphPath);
    }

    const callGraph = JSON.parse(fs.readFileSync(callGraphPath , 'utf8'));
    const entryFileIndices = getFileIndicesForPaths(callGraph , callGraph.entries);
    const entryFunIndices = getFunctionsInFiles(callGraph , entryFileIndices);
    const adjacencyMap = buildAdjacencyMap(callGraph.fun2fun);

    const data = { callGraph , entryFunIndices , adjacencyMap };
    callGraphCache.set(callGraphPath , data);
    return data;
}

export function checkReachability(callGraphPath , packageName,packageVersion ,repoName){
       const { callGraph , entryFunIndices , adjacencyMap } = loadCallGraphData(callGraphPath);

       const repoRootDir = path.join(__dirname , '..' , 'target-repos' , repoName);
       const vulnerableFileIndices = getVulnerablePackageFileIndices(callGraph , packageName , packageVersion , repoRootDir);
       const vulnerableFunIndices = getFunctionsInFiles(callGraph , vulnerableFileIndices);

       const reachablePaths = findReachablePath(entryFunIndices , vulnerableFunIndices , adjacencyMap);

      return { reachable: reachablePaths !== null, path: reachablePaths };
}

export function checkReachabilityForRepo(repoName , packageName , packageVersion){
       const callGraphDirectory = path.join(__dirname , '..' , 'callgraphs');
       const callGraphsNames  = (fs.readdirSync(callGraphDirectory)).filter((callGraph)=>
                             callGraph.startsWith(`${repoName}__`) &&
                             callGraph.endsWith('.json')
                            );
       const results =  callGraphsNames.map((filename)=>{
                         const fullPath = path.join(callGraphDirectory , filename);
                         const result = checkReachability(fullPath , packageName , packageVersion , repoName);

                         return {
                             entryPoint : filename,
                             reachable : result.reachable,
                             path : result.path
                         }
                       });
       return results;
}