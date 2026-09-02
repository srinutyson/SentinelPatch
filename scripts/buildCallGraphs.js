import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import { spawnSync } from 'child_process';


const __dirname = path.dirname(fileURLToPath(import.meta.url));

function getLocalImports(filePath){
        const source = fs.readFileSync(filePath , 'utf-8');

        let ast ;
        try{
            ast = acorn.parse(source , {
                 ecmaVersion : 'latest',
                 sourceType : 'module',
                 allowReturnOutsideFunction : true,
            });
        }catch(error){
             console.warn(`Failed to parse ${filePath}: ${error.message}`);
             return [];
        }

        const rawImportPaths = [];

        walk.simple(ast , {
             ImportDeclaration(node){
                rawImportPaths.push(node.source.value);
             },
             CallExpression(node){
                 if(
                     node.callee.type === 'Identifier' &&
                     node.callee.name === 'require' &&
                     node.arguments.length >0 &&
                     node.arguments[0].type === 'Literal' &&
                     typeof node.arguments[0].value === 'string'
                 ){
                    rawImportPaths.push(node.arguments[0].value);
                 }
             },
        });

        const localImportPaths = rawImportPaths.filter(
            (p) => p.startsWith('./') || p.startsWith('../')
        );

        const resolved = localImportPaths
                           .map((importPath) => resolveModulePath(path.dirname(filePath) , importPath))
                           .filter((p) => p !== null);
        
        return [...new Set(resolved)];
}

function resolveModulePath(fromDir , importPath){
      const base = path.resolve(fromDir , importPath);
      const candidates = [
          base , 
          `${base}.js`,
          `${base}.mjs`,
          `${base}.cjs`,
          path.join(base , 'index.js'),
      ];

      for(const candidate of candidates){
         if(fs.existsSync(candidate) && fs.statSync(candidate).isFile()){
              return candidate;
         }
      }
      console.warn(`Could not resolve import "${importPath}" from ${fromDir}`);
     return null;
}

  function discoveryEntryPoints(mainFilePath){
       return getLocalImports(mainFilePath);
  }

  function runJellyOnFile(filePath , outputName , heapSizeMB = 4096){
         const jsonOut = path.join(__dirname , '..' ,'callgraphs' , `${outputName}.json`);
         const htmlOut = path.join(__dirname , '..' , 'callgraphs' , `${outputName}.html`);


         const result = spawnSync(
             'jelly' ,
             ['-j' , jsonOut , '-m' , htmlOut , filePath],
             {
                env :{
                     ...process.env,
                     NODE_OPTIONS : `--max-old-space-size=${heapSizeMB}`,
                },
                timeout : 10 * 60 * 1000,
                stdio : 'pipe',
             }
         );

         return {
             success : result.status === 0,
             error : result.status !== 0 ? (result.stderr?.toString() || 'unknown error') : null,
         };
  }

  function processEntryPoint(filePath , results = [] , visited = new Set() , depth = 0){
      if(visited.has(filePath) || depth > 5){
         return results;
      }

      visited.add(filePath);

      const outputName = path.relative(path.join(__dirname, '..' , 'target-repos') , filePath)
                         .replace(/[\\/]/g , '__')
                         .replace(/\.js$/ , '');
      console.log(`${' '.repeat(depth)}Analyzing: ${filePath}`);
      const {success , error} = runJellyOnFile(filePath , outputName);
      if(success){
          console.log(`${' '.repeat(depth)} ✅ succeeded`);
          results.push({filePath , outputName , status : 'success'});
          return results;
      }

       console.log(`${' '.repeat(depth)}  ❌ failed, attempting to split further`);
       const localImports = getLocalImports(filePath);

       if(localImports.length === 0){
         console.log(`${'  '.repeat(depth)}  no further local imports to split — leaving as unresolved leaf`);
         results.push({ filePath, outputName, status: 'failed', error });
         return results;
       }

       for(const importedFile of localImports){
          processEntryPoint(importedFile , results , visited , depth+1);
       }

       return results;
  }

  function buildAllCallGraphs(mainFilePath){
      const entryPoints = discoveryEntryPoints(mainFilePath);
      console.log(`Discovered ${entryPoints.length} initial entry points from ${mainFilePath}`);


      const results = [];
       const visited = new Set();

      for(const entryPoint of entryPoints){
          processEntryPoint(entryPoint , results,visited);
      }

      return results;
  }

  const mainFile = path.join(__dirname , '..' , 'target-repos' , 'hackathon-starter' , 'app.js');
   
  const results = buildAllCallGraphs(mainFile);

   console.log('\n--- Summary ---');
   console.log(`Succeeded: ${results.filter((r) => r.status === 'success').length}`);
   console.log(`Failed (leaf, could not split further): ${results.filter((r) => r.status === 'failed').length}`);
   console.log(JSON.stringify(results, null, 2));