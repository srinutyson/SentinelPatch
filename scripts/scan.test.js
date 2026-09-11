import path from 'path';
import { fileURLToPath } from 'url';
import { runScan } from '../index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('runScan — real integration test through the public package entry point', () => {
    test(
        'scanning vuln-fixture with skipAgent finds the known vulnerable package via the real index.js export',
        async () => {
            const repoPath = path.join(__dirname, '..', 'target-repos', 'vuln-fixture');

            const summary = await runScan(repoPath, { skipAgent: true });

            expect(summary.repoPath).toBe(repoPath);
            expect(summary.agentRan).toBe(false);
            expect(summary.vulnerablePackageCount).toBeGreaterThan(0);
            expect(summary.exploitableCount).toBe(0);
        },
        60000,
    );
});
