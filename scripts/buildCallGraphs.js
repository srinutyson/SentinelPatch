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
  
  function loadVulnerablePackages(reponame){
     const reportPath = path.join(__dirname , '..' , `vulnerabilities-${reponame}.json`);
     if(!fs.existsSync(reportPath)){
        console.warn(`No vulnerability report found at ${reportPath} — run: node scripts/queryVulnerabilities.js ${reponame}`);
        return [];
     }
     const report = JSON.parse(fs.readFileSync(reportPath , 'utf-8'));
     const names = report
                   .filter((dep)=> dep.vulnerabilities && dep.vulnerabilities.length >0)
                   .map((dep)=> dep.name);
     return [...new Set(names)]
  }

  function runJellyOnFile(filePath , outputName ,{ heapSizeMB = 4096 , includeOnly = null} = {}){
         const jsonOut = path.join(__dirname , '..' ,'callgraphs' , `${outputName}.json`);
         const htmlOut = path.join(__dirname , '..' , 'callgraphs' , `${outputName}.html`);
         const args = ['-j' , jsonOut , '-m' , htmlOut];
         if(includeOnly && includeOnly.length > 0){
             args.push('--include-packages' , ...includeOnly);
         }
         args.push(filePath)
         const result = spawnSync(
             'jelly' ,
              args,
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

  function processEntryPoint(reponame , filePath , results = [] , visited = new Set() , depth = 0){
      if(visited.has(filePath) || depth > 5){
         return results;
      }

      visited.add(filePath);

      const outputName = path.relative(path.join(__dirname, '..' , 'target-repos') , filePath)
                         .replace(/[\\/]/g , '__')
                         .replace(/\.js$/ , '');
      console.log(`${' '.repeat(depth)}Analyzing: ${filePath}`);
      const first  = runJellyOnFile(filePath , outputName);
      if(first.success){
          console.log(`${' '.repeat(depth)} ✅ succeeded`);
          results.push({filePath , outputName , status : 'success'});
          return results;
      }

       console.log(`${' '.repeat(depth)}  ❌ failed, attempting to split further`);
       const localImports = getLocalImports(filePath);

       if(localImports.length === 0){
         console.log(`${'  '.repeat(depth)}  no further local imports to split — retrying scoped to known-vulnerable packages only`);

         const vulnerablePackages = loadVulnerablePackages(reponame);
         if(vulnerablePackages.length > 0){
             const scoped = runJellyOnFile(filePath , outputName , {includeOnly : vulnerablePackages});
             if(scoped.success){
                 console.log(`${'  '.repeat(depth)}  ✅ succeeded (scoped to: ${vulnerablePackages.join(', ')})`);
                 results.push({filePath , outputName , status : 'success' , scopedTo : vulnerablePackages});
                 return results;
                }
             console.log(`${'  '.repeat(depth)}  ❌ still failed even scoped to vulnerable packages only`);
             results.push({ filePath, outputName, status: 'failed', error: scoped.error });
             return results;
         }
         console.log(`${'  '.repeat(depth)}  no known-vulnerable packages found — leaving as unresolved leaf`);
         results.push({ filePath, outputName, status: 'failed', error: first.error });
         return results;
       }

       for(const importedFile of localImports){
          processEntryPoint(reponame,importedFile , results , visited , depth+1);
       }

       return results;
  }

  function buildAllCallGraphs(mainFilePath,reponame){
      const entryPoints = discoveryEntryPoints(mainFilePath);
      console.log(`Discovered ${entryPoints.length} initial entry points from ${mainFilePath}`);
     

      const results = [];
       const visited = new Set();

      for(const entryPoint of entryPoints){
          processEntryPoint(reponame , entryPoint , results,visited);
      }

      return results;
  }
 const reponame = process.argv[2] || 'hackathon-starter';
 const mainFile = path.join(__dirname , '..' , 'target-repos' , reponame , 'app.js');

  const results = buildAllCallGraphs(mainFile,reponame);

   console.log('\n--- Summary ---');
   console.log(`Succeeded: ${results.filter((r) => r.status === 'success').length}`);
   console.log(`Failed (leaf, could not split further): ${results.filter((r) => r.status === 'failed').length}`);
   console.log(JSON.stringify(results, null, 2));