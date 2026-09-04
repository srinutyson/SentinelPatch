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

  function loadLockfile(reponame){
     const lockPath = path.join(__dirname , '..' , 'target-repos' , reponame , 'package-lock.json');
     if(!fs.existsSync(lockPath)){
        console.warn(`No package-lock.json found for ${reponame} — skipping ancestor-package expansion`);
        return null;
     }
     return JSON.parse(fs.readFileSync(lockPath , 'utf-8'));
  }

  function buildReverseDependencyMap(lockJson){
     const reverseMap = new Map(); // depName -> Set of package names that directly require it

     for(const [key, entry] of Object.entries(lockJson.packages || {})){
        if(key === '') continue;
        const name = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
        const deps = entry.dependencies ? Object.keys(entry.dependencies) : [];
        for(const dep of deps){
           if(!reverseMap.has(dep)){
              reverseMap.set(dep, new Set());
           }
           reverseMap.get(dep).add(name);
        }
     }
     return reverseMap;
  }

  function getAncestorPackages(reverseMap, targetPackage){
     const ancestors = new Set();
     const queue = [targetPackage];
     const seen = new Set([targetPackage]);

     while(queue.length > 0){
        const current = queue.shift();
        const requirers = reverseMap.get(current);
        if(!requirers) continue;

        for(const requirer of requirers){
           if(!seen.has(requirer)){
              seen.add(requirer);
              ancestors.add(requirer);
              queue.push(requirer);
           }
        }
     }
     return ancestors;
  }

  function getScopedIncludeList(reponame, vulnerablePackages){
     const lockJson = loadLockfile(reponame);
     if(!lockJson) return vulnerablePackages;

     const reverseMap = buildReverseDependencyMap(lockJson);
     const fullSet = new Set(vulnerablePackages);

     for(const pkg of vulnerablePackages){
        const ancestors = getAncestorPackages(reverseMap, pkg);
        for(const ancestor of ancestors){
           fullSet.add(ancestor);
        }
     }

     return [...fullSet];
  }

  function runJellyOnFile(filePath , outputName ,{ heapSizeMB = 4096 , includeOnly = null} = {}){
         const jsonOut = path.join(__dirname , '..' ,'callgraphs' , `${outputName}.json`);
         const htmlOut = path.join(__dirname , '..' , 'callgraphs' , `${outputName}.html`);
         const args = ['-j', jsonOut, '-m', htmlOut, filePath];
         if (includeOnly && includeOnly.length > 0) {
            args.push('--include-packages', ...includeOnly);
         }
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
         const outputExists = fs.existsSync(jsonOut);
         return {
             success : result.status === 0 && outputExists,
             error : result.status !== 0 ? (result.stderr?.toString() || 'unknown error') : (!outputExists ? (result.stdout?.toString() || 'jelly exited 0 but produced no output file') : null),
         };
  }

  function processEntryPoint(reponame , filePath , results = [] , visited = new Set() , depth = 0){
    if(visited.has(filePath)){
        console.log(`${' '.repeat(depth)}⏭ skipping ${filePath} — already covered by another entry point's call graph`);
        results.push({ filePath, status: 'subsumed', note: 'already covered by another entry point\'s call graph' });
        return results;
    }

    if(depth > 5){
        console.log(`${' '.repeat(depth)}❌ giving up on ${filePath} — max split depth (5) exceeded`);
        results.push({ filePath, status: 'failed', error: 'max recursion depth exceeded while splitting' });
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

    console.log(`${' '.repeat(depth)}  ❌ failed, attempting scoped retry on this file`);

    const baseVulnerablePackages = loadVulnerablePackages(reponame);
    const vulnerablePackages = getScopedIncludeList(reponame, baseVulnerablePackages);
    let ownScopedSucceeded = false;

    if(vulnerablePackages.length > 0){
        const scoped = runJellyOnFile(filePath , outputName , {includeOnly : vulnerablePackages , heapSizeMB : 6144,});
        if(scoped.success){
            console.log(`${'  '.repeat(depth)}  ✅ succeeded (scoped to: ${vulnerablePackages.join(', ')})`);
            results.push({filePath , outputName , status : 'success' , scopedTo : vulnerablePackages});
            ownScopedSucceeded = true;
        } else {
            console.log(`${'  '.repeat(depth)}  ❌ scoped retry on this file also failed`);
        }
    } else {
        console.log(`${'  '.repeat(depth)}  no known-vulnerable packages found — skipping scoped retry`);
    }

    const localImports = getLocalImports(filePath);

    if(localImports.length === 0){
        if(!ownScopedSucceeded){
            console.log(`${'  '.repeat(depth)}  no local imports to split — leaving as unresolved leaf`);
            results.push({ filePath, outputName, status: 'failed', error: first.error });
        }
        return results;
    }

    if(!ownScopedSucceeded){
        results.push({ filePath, outputName, status: 'failed', error: first.error, note: 'own scope failed — falling back to analyzing local imports separately' });
    }

    console.log(`${'  '.repeat(depth)}  also splitting into local imports for supplementary coverage`);
    for(const importedFile of localImports){
       processEntryPoint(reponame,importedFile , results , visited , depth+1);
    }

    return results;
}

  function buildAllCallGraphs(mainFilePath,reponame){

    const results = [];
    const visited = new Set();

    console.log(`Analyzing main entry file itself: ${mainFilePath}`);
    processEntryPoint(reponame, mainFilePath, results, visited);

    const entryPoints = discoveryEntryPoints(mainFilePath);
    console.log(`Discovered ${entryPoints.length} initial entry points from ${mainFilePath}`);



      for(const entryPoint of entryPoints){
          processEntryPoint(reponame , entryPoint , results,visited);
      }

      return results;
  }
   function resolveExportsField(exportsValue){
      if(!exportsValue) return null;

      if(typeof exportsValue === 'string'){
          return exportsValue;
      }

      if(typeof exportsValue !== 'object') return null;

      const keys = Object.keys(exportsValue);
      const isSubpathMap = keys.some((k)=> k.startsWith('.'));

      const conditions = isSubpathMap ? exportsValue['.'] : exportsValue;
      if(!conditions) return null;

      if(typeof conditions === 'string'){
          return conditions;
      }
      if(typeof conditions === 'object'){
         return (
              conditions.require||
              conditions.node||
              conditions.default||
              conditions.import||
              null
         );
      }
      return null;
   }
   function getMainFile(reponame){
      const repoPath = path.join(__dirname , '..' , 'target-repos',reponame);
      const pkgJsonPath = path.join(repoPath , 'package.json');
      const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath , 'utf8'));
      const candidates = [];
      const startCandidate = extractEntryFromStartScript(pkgJson.scripts?.start);
      if(startCandidate) candidates.push(startCandidate);
      const exportsCandidate  = resolveExportsField(pkgJson.exports) ||pkgJson.main || 'index.js';
      if(exportsCandidate) candidates.push(exportsCandidate);

       candidates.push('index.js','app.js' , 'server.js', 'main.js');
      for(const candidate of candidates){
           const resolved = resolveModulePath(repoPath , candidate);
           if(resolved){
            console.log(resolved);
               return resolved;

           }
      }


           throw new Error(
            `Could not resolve entry file for "${reponame}" — tried "${candidates.join(', ')}" ` +
            `(from package.json "exports"/"main", or the "index.js" default) but no matching file exists.`
        );



   }

   function extractEntryFromStartScript(startScript){
      if(!startScript) return null;

      const knownRunners = new Set(['node' , 'nodemon' , 'ts-node' , 'babel-node' , 'npx']);
      const tokens = startScript.trim().split(/\s+/);

     for(let i = 0; i < tokens.length; i++) {
        if (knownRunners.has(tokens[i])) {
            for (let j = i + 1; j < tokens.length; j++) {
                if (tokens[j].startsWith('-')) continue; // flag, skip it
                return tokens[j];
            }
        }
    }

    for(const token of tokens) {
        if (/\.(js|mjs|cjs)$/.test(token) || token.includes('/')) {
            return token;
        }
    }


      return null;
   }

 const reponame = process.argv[2] || 'hackathon-starter';
 const mainFile = getMainFile(reponame)

  const results = buildAllCallGraphs(mainFile,reponame);

   console.log('\n--- Summary ---');
   console.log(`Succeeded: ${results.filter((r) => r.status === 'success').length}`);
   console.log(`Failed (leaf, could not split further): ${results.filter((r) => r.status === 'failed').length}`);
   console.log(JSON.stringify(results, null, 2));
