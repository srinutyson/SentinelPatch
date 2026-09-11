#!/usr/bin/env node
import { Command } from 'commander';
import { runScan } from '../scripts/scan.js';

const program = new Command();

program
    .name('sentinelpatch')
    .description('Determine which known CVEs in your dependencies are actually reachable and exploitable');

program
    .command('scan')
    .description('Scan a repository for reachable, exploitable CVEs')
    .argument('[path]', 'Path to the repository to scan', '.')
    .option('--skip-agent', 'Skip the AI exploitability judgment step (reachability only)')
    .option('--output <format>', 'Output format: table, json, or markdown', 'table')
    .option('--out-file <path>', 'Write the report to a file instead of stdout')
    .action(async (path, cmdOptions) => {
        await runScan(path, {
            skipAgent: cmdOptions.skipAgent || false,
            output: cmdOptions.output,
            outFile: cmdOptions.outFile,
        });
    });

program.parse();
