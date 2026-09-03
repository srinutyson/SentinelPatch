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


export function isReachable(startFuncIds , targetFuncids , adjacencyMap){
       const queue = [...startFuncIds];
     
       const visited = new Set(startFuncIds);

       while(queue.length > 0){
            const current = queue.shift();
            if(targetFuncids.has(current)) return true;
            const callees = adjacencyMap.get(current) || [];
            for(const callee of callees){
                 if(visited.has(callee))continue;
                 visited.add(callee);
                 queue.push(callee);
            }

       }
       return false;
}
