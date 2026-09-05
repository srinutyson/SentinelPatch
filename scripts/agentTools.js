import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function readSourceLines(repoName , filePath , startLine , endLine , contextLines = 5){
     const  absolutePath = path.join(__dirname , '..' , 'target-repos' , repoName , filePath);
     const source  = fs.readFileSync(absolutePath , 'utf-8');
     const lines = source.split('\n');

     const from = Math.max(0 , startLine - 1 - contextLines);
     const to = Math.min(lines.length , endLine + contextLines);

     const sliceLines = lines.slice(from , to);

     return sliceLines.map((line , i)=> `${i+from+1}: ${line}`) .join('\n');

}


export function readFunctionBody(repoName , location){
       return readSourceLines(repoName , location.file , location.startLine , location.endLine , 0);
}


export const readSourceLinesDeclaration = {
    name: 'readSourceLines',
    description: 'Read a range of source code lines from a file in the target repo, with optional surrounding context lines, to inspect real code around a location in a call path.',
    parameters: {
        type: 'object',
        properties: {
            filePath: {
                type: 'string',
                description: 'Path to the file, relative to the target repo root (e.g. "routes/merge.js" or "node_modules/lodash/lodash.js").',
            },
            startLine: {
                type: 'integer',
                description: 'First line of the range to read.',
            },
            endLine: {
                type: 'integer',
                description: 'Last line of the range to read.',
            },
            contextLines: {
                type: 'integer',
                description: 'Number of extra lines to include before startLine and after endLine. Defaults to 5.',
            },
        },
        required: ['filePath', 'startLine', 'endLine'],
    },
};

export const readFunctionBodyDeclaration = {
    name: 'readFunctionBody',
    description: 'Read the exact source code of one function, given a resolved location object from a Finding\'s path (funcId, file, startLine, endLine). No extra context lines.',
    parameters: {
        type: 'object',
        properties: {
            file: {
                type: 'string',
                description: 'Path to the file, relative to the target repo root.',
            },
            startLine: {
                type: 'integer',
            },
            endLine: {
                type: 'integer',
            },
        },
        required: ['file', 'startLine', 'endLine'],
    },
};