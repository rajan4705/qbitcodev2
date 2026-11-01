import { Command } from 'commander';
import { handleScan, handleReview, handleFastScan } from './scan-cmd.js';
import { handleFix } from './fix-cmd.js';
import { handleChat } from './chat-cmd.js';
import { handleModelList, handleModelSwitch } from './model-cmd.js';
import { startServer } from '../server/app.js';
import { config } from '../core/config.js';
import open from 'open';
import chalk from 'chalk';

export function createCli() {
  const program = new Command();

  program
    .name('qbit')
    .description('Qbit Code Reviewer: Autonomous AI-Powered Code Review and Remediation Engine')
    .version('1.0.0');

  program
    .command('fastscan [targetPath]')
    .description('Analyze directory & subdirectories, identify exempt folders/files, and accelerate scan')
    .option('-p, --path <path>', 'Directory or file path to analyze')
    .option('-f, --format <format>', 'Output format: text, json', 'text')
    .option('--run-scan', 'Immediately trigger full scan with generated exemptions', false)
    .action((targetPath, options) => handleFastScan(targetPath, options));

  program
    .command('scan [targetPath]')
    .description('Run vulnerability & code defect analysis on the repository')
    .option('-p, --path <path>', 'Directory or file path to scan')
    .option('-e, --exclude <patterns>', 'Comma-separated glob patterns to exclude from scan')
    .option('-f, --format <format>', 'Output format: text, json, sarif, csv', 'text')
    .option('-o, --output <file>', 'Save results to output file')
    .option('--patches [boolean]', 'Include synthesized patches in output (default: true)', true)
    .option('--enrich [boolean]', 'Enrich findings with MITRE CWE & CVE identifiers (default: true)', true)
    .option('--min-severity <level>', 'Minimum severity filter (critical, high, medium, all)', 'high')
    .option('--no-resume', 'Do not resume previous interrupted session')
    .option('--no-cache', 'Do not use scan cache')
    .action((targetPath, options) => handleScan(targetPath, options));

  program
    .command('review')
    .description('Review git uncommitted or branch changes')
    .option('--staged', 'Review staged git changes only', false)
    .option('--from <ref>', 'Base branch or commit')
    .option('--to <ref>', 'Target branch or commit')
    .option('--commit <hash>', 'Review a specific commit')
    .option('-f, --format <format>', 'Output format: text, json, sarif', 'text')
    .option('-o, --output <file>', 'Save results to output file')
    .action((options) => handleReview(options));

  program
    .command('fix')
    .description('Autonomously update files based on review suggestions using QbitCode')
    .option('--id <id>', 'Specific finding ID to fix (e.g. 1)')
    .option('--all', 'Fix all detected vulnerabilities', false)
    .action((options) => handleFix(options));

  program
    .command('chat')
    .description('Start interactive chat with Qbit Code Reviewer powered by local vLLM')
    .option('--finding <id>', 'Pre-seed chat with a specific finding context')
    .action((options) => handleChat(options));

  program
    .command('vllm [action] [variant]')
    .alias('model')
    .description('Inspect or switch local vLLM backend AI model (14b or 30b)')
    .action(async (action, variant) => {
      if (action === 'switch') {
        await handleModelSwitch(variant);
      } else if (action === '14b' || action === '30b') {
        await handleModelSwitch(action);
      } else {
        await handleModelList();
      }
    });

  program
    .command('ui')
    .description('Launch the Qbit Web Cockpit in your browser')
    .option('-p, --port <port>', 'Port to listen on', String(config.port))
    .option('-w, --workspace <path>', 'Workspace directory to open')
    .option('--no-open', 'Do not automatically open the browser')
    .action(async (options) => {
      let port = parseInt(options.port, 10);

      // Check if port is in use and find an available port if needed
      const net = await import('node:net');
      const isPortFree = (p) => new Promise(resolve => {
        const tester = net.createServer()
          .once('error', () => resolve(false))
          .once('listening', () => tester.close(() => resolve(true)))
          .listen(p);
      });

      const initialPort = port;
      while (!(await isPortFree(port)) && port < initialPort + 10) {
        port++;
      }
      if (port !== initialPort) {
        console.log(chalk.yellow(`⚠️  Port ${initialPort} is in use (e.g. system postgres). Switched to port ${port}.`));
      }

      if (options.workspace) {
        try {
          process.chdir(options.workspace);
        } catch (e) {
          console.error(`Failed to change to workspace directory: ${options.workspace}`);
        }
      }
      const server = startServer(port);
      const url = `http://localhost:${port}`;
      console.log(chalk.cyan.bold(`\n🚀 Qbit Code Reviewer Web Cockpit launched at: ${chalk.underline(url)}`));
      console.log(chalk.dim(`   Workspace: ${process.cwd()}`));
      console.log(chalk.dim(`   Powered by local vLLM (${config.model}), OCR, and QbitCode\n`));

      if (options.open !== false) {
        try {
          await open(url);
        } catch {}
      }

      // Explicitly keep the process alive
      setInterval(() => {}, 1000 * 60 * 60);
    });

  return program;
}
