import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
      buildAdjacencyMap , 
      isReachable,
      findReachablePath,
      getFileIndicesForPaths,
      getFunctionsInFiles,
      checkReachability
} from './reachability.js';


const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('buildAdjacencyMap' , ()=>{
      test('maps each caller to its list of callees' , ()=>{
           const map = buildAdjacencyMap([[1, 2], [1, 3], [2, 4]]);
           expect(map.get(1)).toEqual([2,3]);
           expect(map.get(2)).toEqual([4]);

      });

      test('a function with no outgoing calls is absent as a key, not present with an empty array' , ()=>{
        const map = buildAdjacencyMap([[1, 2], [1, 3], [2, 4]]);
        expect(map.has(4)).toBe(false);
      });
});


describe('isReachable', () => {
    const map = buildAdjacencyMap([[1, 2], [2, 3]]);

    test('finds a target reachable through a chain of calls', () => {
        expect(isReachable([1], new Set([3]), map)).toBe(true);
    });

    test('returns false when the target has no incoming path', () => {
        expect(isReachable([1], new Set([4]), map)).toBe(false);
    });

    test('a start node that is also the target counts as reachable', () => {
        expect(isReachable([1], new Set([1]), map)).toBe(true);
    });
});

describe('findReachablePath', () => {
    test('returns the shorter of two possible paths', () => {
        const map = buildAdjacencyMap([[1, 2], [2, 3], [3, 5], [1, 4], [4, 5]]);
        const result = findReachablePath([1], new Set([5]), map);
        expect(result).toEqual([1, 4, 5]);
    });

    test('returns null when the target is genuinely unreachable', () => {
        const map = buildAdjacencyMap([[1, 2], [2, 3]]);
        const result = findReachablePath([1], new Set([99]), map);
        expect(result).toBeNull();
    });
});

describe('cycle handling', () => {
    const map = buildAdjacencyMap([[1, 2], [2, 3], [3, 1], [3, 4]]);

    test('isReachable terminates correctly on a graph containing a cycle', () => {
        expect(isReachable([1], new Set([4]), map)).toBe(true);
    });

    test('findReachablePath terminates and returns a valid path on a graph containing a cycle', () => {
        const result = findReachablePath([1], new Set([4]), map);
        expect(result).toEqual([1, 2, 3, 4]);
    });
});

describe('getFunctionsInFiles', () => {
    test('matches funcIds by file index and returns them as real Numbers', () => {
        const callGraph = {
            functions: {
                '10': '0:1:1:5:5',
                '20': '1:1:1:5:5',
            },
        };
        const result = getFunctionsInFiles(callGraph, new Set([0]));
        expect(result).toEqual(new Set([10]));
        const [onlyValue] = result;
        expect(typeof onlyValue).toBe('number');
    });
});

describe('getFileIndicesForPaths', () => {
    test('exact-matches file paths against callGraph.files', () => {
        const callGraph = { files: ['a.js', 'b.js', 'c.js'] };
        const result = getFileIndicesForPaths(callGraph, ['b.js']);
        expect(result).toEqual(new Set([1]));
    });
});

describe('checkReachability — integration test on the real vuln-fixture call graph', () => {
    test('confirms the known real positive case: lodash prototype pollution reachable via app.js -> routes/merge.js -> lodash.js', () => {
        const callGraphPath = path.join(__dirname, '..', 'callgraphs', 'vuln-fixture__app.json');
        const result = checkReachability(callGraphPath, 'lodash', '4.17.15', 'vuln-fixture');

        expect(result.reachable).toBe(true);
        expect(result.status).toBe('reachable');
        expect(result.path).toEqual([1577, 1579, 1581]);
    });
});