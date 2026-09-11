import fs from 'fs';
import { resolveScanContext, ensureOutputDirs } from './projectPaths.js';
import { writeVulnerabilityReport } from './queryVulnerabilities.js';
import { getMainFile, buildAllCallGraphs } from './buildCallGraphs.js';
import { runAgentOnRepo } from './runAgent.js';
import { generateFindings, generateUnresolvedFindings } from './agentSchemas.js';

function buildSummary(ctx, findings, unresolved, verdictsOutput){
    const vulnerabilities = fs.existsSync(ctx.vulnerabilitiesPath)
        ? JSON.parse(fs.readFileSync(ctx.vulnerabilitiesPath, 'utf-8'))
        : [];
    const vulnerablePackages = vulnerabilities.filter((dep) => dep.vulnerabilities && dep.vulnerabilities.length > 0);

    const exploitable = verdictsOutput
        ? verdictsOutput.verdicts.filter((v) => v.verdict === 'exploitable')
        : [];

    return {
        repoPath: ctx.repoPath,
        projectId: ctx.projectId,
        vulnerablePackageCount: vulnerablePackages.length,
        reachableFindingCount: findings.length,
        unresolvedCount: unresolved.length,
        agentRan: verdictsOutput !== null,
        exploitableCount: exploitable.length,
        exploitable,
    };
}

function formatTable(summary){
    const lines = [];
    lines.push(`Scan target: ${summary.repoPath}`);
    lines.push(`Vulnerable packages found: ${summary.vulnerablePackageCount}`);
    lines.push(`Reachable findings (proven call path exists): ${summary.reachableFindingCount}`);
    lines.push(`Inconclusive (incomplete call-graph coverage): ${summary.unresolvedCount}`);
    if(summary.agentRan){
        lines.push(`Exploitable (agent-confirmed): ${summary.exploitableCount}`);
        if(summary.exploitableCount > 0){
            lines.push('');
            lines.push('Exploitable findings:');
            for(const v of summary.exploitable){
                lines.push(`  - ${v.cveId} (confidence ${v.confidence})`);
                lines.push(`    ${v.reasoning}`);
            }
        }
    } else {
        lines.push('Agent step skipped (skipAgent option was set) — exploitability not judged, reachability data above is still real.');
    }
    return lines.join('\n');
}

function formatMarkdown(summary){
    const lines = [];
    lines.push(`# SentinelPatch scan report`);
    lines.push('');
    lines.push(`**Target:** \`${summary.repoPath}\``);
    lines.push(`**Vulnerable packages found:** ${summary.vulnerablePackageCount}`);
    lines.push(`**Reachable findings (proven call path exists):** ${summary.reachableFindingCount}`);
    lines.push(`**Inconclusive (incomplete call-graph coverage):** ${summary.unresolvedCount}`);
    if(summary.agentRan){
        lines.push(`**Exploitable (agent-confirmed):** ${summary.exploitableCount}`);
        lines.push('');
        if(summary.exploitableCount > 0){
            lines.push('## Exploitable findings');
            lines.push('');
            for(const v of summary.exploitable){
                lines.push(`### ${v.cveId} (confidence ${v.confidence})`);
                lines.push('');
                lines.push(v.reasoning);
                lines.push('');
            }
        }
    } else {
        lines.push('');
        lines.push('_Agent step skipped (skipAgent option was set) — exploitability not judged, reachability data above is still real._');
    }
    return lines.join('\n');
}

function formatSummary(summary, format){
    if(format === 'json'){
        return JSON.stringify(summary, null, 2);
    }
    if(format === 'markdown'){
        return formatMarkdown(summary);
    }
    return formatTable(summary);
}

export async function runScan(inputPath, options = {}){
    const { skipAgent = false, output = 'table', outFile = null } = options;

    const ctx = resolveScanContext(inputPath);
    ensureOutputDirs(ctx);

    console.log(`Scanning ${ctx.repoPath}...`);

    await writeVulnerabilityReport(ctx);

    console.log('Building call graphs...');
    const mainFile = getMainFile(ctx);
    const coverageResults = buildAllCallGraphs(mainFile, ctx);
    fs.writeFileSync(ctx.coveragePath, JSON.stringify(coverageResults, null, 2));

    console.log('Checking reachability...');
    const findings = generateFindings(ctx);
    const unresolved = generateUnresolvedFindings(ctx);

    let verdictsOutput = null;
    if(!skipAgent){
        console.log('Running agent verdicts...');
        verdictsOutput = await runAgentOnRepo(ctx, { findings, unresolved });
    }

    const summary = buildSummary(ctx, findings, unresolved, verdictsOutput);
    const formatted = formatSummary(summary, output);

    if(outFile){
        fs.writeFileSync(outFile, formatted);
        console.log(`\nReport written to ${outFile}`);
    } else {
        console.log('\n' + formatted);
    }

    return summary;
}
