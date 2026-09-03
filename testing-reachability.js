import fs from 'fs';
import {
    getVulnerablePackageFileIndices,
    getFunctionsInFiles,
    getFileIndicesForPaths,
} from './scripts/reachability.js';

const callGraph = JSON.parse(
    fs.readFileSync('callgraphs/vuln-fixture__routes__merge.json', 'utf-8')
);


const vulnFileIndices = getVulnerablePackageFileIndices(callGraph, 'lodash');
const targetFuncIds = getFunctionsInFiles(callGraph, vulnFileIndices);
console.log('Target function count (lodash):', targetFuncIds.size);


console.log('callGraph.entries:', callGraph.entries);
const entryFileIndices = getFileIndicesForPaths(callGraph, callGraph.entries);
console.log('Entry file indices:', [...entryFileIndices]);

const startFuncIds = getFunctionsInFiles(callGraph, entryFileIndices);
console.log('Start function count:', startFuncIds.size);

const sample = [...startFuncIds].slice(0, 5);
console.log('Sample start funcIds and their locations:');
for (const id of sample) {
    console.log(`  funcId ${id} -> ${callGraph.functions[id]}`);
}