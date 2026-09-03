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





