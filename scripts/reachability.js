import { full } from 'acorn-walk';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

export function getVulnerablePackageFileIndices(callGraph , packageName){
     const indices = new Set();
       callGraph.files.forEach((filePath , index)=>{
            if(filePath.includes(`node_modules/${packageName}/`)){
                indices.add(index);
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

export function checkReachability(callGraphPath , packageName){
       const callGraph  = JSON.parse(fs.readFileSync(callGraphPath , 'utf8'));
       const vulnerableFileIndices = getVulnerablePackageFileIndices(callGraph , packageName);
       const vulnerableFunIndices =  getFunctionsInFiles(callGraph , vulnerableFileIndices);
       const entryFileIndices = getFileIndicesForPaths(callGraph , callGraph.entries);
       const entryFunIndices = getFunctionsInFiles(callGraph , entryFileIndices);
       const adjacencyMap = buildAdjacencyMap(callGraph.fun2fun);
       const reachablePaths = findReachablePath(entryFunIndices , vulnerableFunIndices , adjacencyMap);
       
      return { reachable: reachablePaths !== null, path: reachablePaths };
}

export function checkReachabilityForRepo(repoName , packageName){

       const __dirname = path.dirname(fileURLToPath(import.meta.url));
       const callGraphDirectory = path.join(__dirname , '..' , 'callgraphs');
       const callGraphsNames  = (fs.readdirSync(callGraphDirectory)).filter((callGraph)=> 
                             callGraph.startsWith(`${repoName}__`) &&
                             callGraph.endsWith('.json')
                            );
       const results =  callGraphsNames.map((filename)=>{
                         const fullPath = path.join(callGraphDirectory , filename);
                         const result = checkReachability(fullPath , packageName);

                         return {
                             entryPoint : filename,
                             reachable : result.reachable,
                             path : result.path
                         }
                       });
       return results
       
}