import path from 'path';
import { fileURLToPath } from 'url';
import { generateFindings } from "./agentSchemas.js";
import { runFindingThroughAgent } from "./agentGraphs.js";
import { resolveScanContext } from "./projectPaths.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('runFindingThroughAgent — real integration test against the Gemini API', () => {
    test(
        'the known real positive case (GHSA-p6mc-m468-83gw) still resolves to a valid, correct exploitable verdict',
        async () => {
            const ctx = resolveScanContext(path.join(__dirname, '..', 'target-repos', 'vuln-fixture'));
            const findings = generateFindings(ctx);
            const finding = findings.find((f) => f.cveId === 'GHSA-p6mc-m468-83gw');

            expect(finding).toBeDefined();

            const verdict = await runFindingThroughAgent(finding, ctx);


            expect(verdict.cveId).toBe('GHSA-p6mc-m468-83gw');
            expect(['exploitable', 'not-exploitable', 'insufficient-evidence']).toContain(verdict.verdict);
            expect(verdict.confidence).toBeGreaterThanOrEqual(0);
            expect(verdict.confidence).toBeLessThanOrEqual(1);
            expect(typeof verdict.reasoning).toBe('string');
            expect(verdict.reasoning.length).toBeGreaterThan(0);
            expect(Array.isArray(verdict.citedEvidence)).toBe(true);


            expect(verdict.verdict).toBe('exploitable');
            expect(verdict.citedEvidence.length).toBeGreaterThan(0);
        },
        60000,
    );
});
