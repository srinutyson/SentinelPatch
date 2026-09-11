import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

export function resolveScanContext(inputPath) {
    const repoPath = path.resolve(inputPath);

    const sanitizedBasename = path.basename(repoPath).replace(/[^a-zA-Z0-9-_]/g, '-');
    const hash = crypto.createHash('sha256').update(repoPath).digest('hex').slice(0, 8);
    const projectId = `${sanitizedBasename}-${hash}`;

    const outputDir = path.join(os.homedir(), '.sentinelpatch', 'projects', projectId);
    const callGraphsDir = path.join(outputDir, 'callgraphs');

    return {
        repoPath,
        projectId,
        outputDir,
        callGraphsDir,
        vulnerabilitiesPath: path.join(outputDir, 'vulnerabilities.json'),
        coveragePath: path.join(outputDir, 'coverage.json'),
        verdictsPath: path.join(outputDir, 'verdicts.json'),
        embeddingsPath: path.join(outputDir, 'embeddings.json'),
    };
}

export function ensureOutputDirs(ctx) {
    fs.mkdirSync(ctx.outputDir, { recursive: true });
    fs.mkdirSync(ctx.callGraphsDir, { recursive: true });
}
