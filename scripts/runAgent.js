import fs from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import 'dotenv/config';
import { runFindingThroughAgent } from "./agentGraphs.js";
import { generateFindings , generateUnresolvedFindings } from "./agentSchemas.js";

const repoName = process.argv[2] || 'vuln-fixture';
const __dirname = path.dirname(fileURLToPath(import.meta.url));

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

const DELAY_BETWEEN_FINDINGS_MS = 60000;

async function runAgentOnRepo(repoName){
    const findings = generateFindings(repoName);
    const unresolved = generateUnresolvedFindings(repoName);

    console.log(`\nRunning agent on ${findings.length} finding(s) for ${repoName}...`);

    const verdicts = [];

    for(let i = 0 ; i<findings.length ; i++){
        const finding = findings[i];
         console.log(`\n[${i + 1}/${findings.length}] Investigating ${finding.cveId} (${finding.packageName}) from ${finding.entryPointFile}...`);
        
         try{
            const verdict = await runFindingThroughAgent(finding);
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
          repoName ,
          generatedAt: new Date().toISOString(),
          verdicts,
          unresolved,
    }

     const outputPath = path.join(__dirname, '..', `verdicts-${repoName}.json`);
    fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
    console.log(`\nWrote ${verdicts.length} verdict(s) and ${unresolved.length} unresolved case(s) to ${outputPath}`);

    return output;
}

   
    runAgentOnRepo(repoName);