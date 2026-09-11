import fs from 'fs';
import { runFindingThroughAgent } from "./agentGraphs.js";
import { generateFindings , generateUnresolvedFindings } from "./agentSchemas.js";
import { resolveScanContext, ensureOutputDirs } from "./projectPaths.js";

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

const DELAY_BETWEEN_FINDINGS_MS = 60000;

export async function runAgentOnRepo(ctx, precomputed = {}){
    ensureOutputDirs(ctx);
    const findings = precomputed.findings || generateFindings(ctx);
    const unresolved = precomputed.unresolved || generateUnresolvedFindings(ctx);

    console.log(`\nRunning agent on ${findings.length} finding(s) for ${ctx.projectId}...`);

    const verdicts = [];

    for(let i = 0 ; i<findings.length ; i++){
        const finding = findings[i];
         console.log(`\n[${i + 1}/${findings.length}] Investigating ${finding.cveId} (${finding.packageName}) from ${finding.entryPointFile}...`);

         try{
            const verdict = await runFindingThroughAgent(finding, ctx);
            verdicts.push(verdict);
              console.log(`  -> ${verdict.verdict} (confidence ${verdict.confidence})`);
         }catch(error){
            console.error(`  -> agent run failed: ${error.message}`);
            verdicts.push({
                  finding,
                verdict: {
                    cveId: finding.cveId,
                    verdict: 'insufficient-evidence',
                    confidence: 0,
                    reasoning: `Agent run failed with an error: ${error.message}`,
                    citedEvidence: [],
                },
            });
         }

         if (i < findings.length - 1) {
            console.log(`  Waiting ${DELAY_BETWEEN_FINDINGS_MS / 1000}s before next finding (rate-limit pacing)...`);
            await sleep(DELAY_BETWEEN_FINDINGS_MS);
        }

    }

    const output = {
          projectId: ctx.projectId,
          repoPath: ctx.repoPath,
          generatedAt: new Date().toISOString(),
          verdicts,
          unresolved,
    }

    fs.writeFileSync(ctx.verdictsPath, JSON.stringify(output, null, 2));
    console.log(`\nWrote ${verdicts.length} verdict(s) and ${unresolved.length} unresolved case(s) to ${ctx.verdictsPath}`);

    return output;
}

if (import.meta.url === `file://${process.argv[1]}`) {
    const repoPathArg = process.argv[2] || 'target-repos/vuln-fixture';
    const ctx = resolveScanContext(repoPathArg);
    await runAgentOnRepo(ctx);
}
