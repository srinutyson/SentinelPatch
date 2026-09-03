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
             matchedFuncIds.add(funcId);
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


