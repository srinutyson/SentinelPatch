import fs from 'fs';
import { getVulnerablePackageFileIndices , getFunctionsInFiles} from './scripts/reachability.js';

const callGraph = JSON.parse(
    fs.readFileSync('callgraphs/vuln-fixture__routes__merge.json', 'utf-8')
);

const fileIndices = getVulnerablePackageFileIndices(callGraph, 'lodash');
console.log('Vulnerable file indices:', [...fileIndices]);

const funcIds = getFunctionsInFiles(callGraph, fileIndices);
console.log('Matched function count:', funcIds.size);

const sample = [...funcIds].slice(0, 3);
console.log('Sample funcIds and their locations:');
for (const id of sample) {
    console.log(`  funcId ${id} -> ${callGraph.functions[id]}`);
}