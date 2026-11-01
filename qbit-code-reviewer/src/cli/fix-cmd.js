import readline from 'node:readline/promises';
import fs from 'node:fs';
import path from 'node:path';
import chalk from 'chalk';
import { runScan } from '../core/ocr-runner.js';
import { applyFixWithOpenCode } from '../core/opencode-runner.js';
import { printFindingsTable } from './formatters.js';

export async function handleFix(options) {
  console.log(chalk.cyan.bold('\n⚡ Qbit Autonomous Remediation Engine'));
  
  console.log(chalk.dim('Gathering latest vulnerability findings...'));
  let findings = [];
  const targetDir = process.cwd();
  const ocrCandidates = [
    path.join(targetDir, 'ocr_output.json'),
    path.join(targetDir, 'qbit_output.json'),
    path.join(targetDir, 'scan-res.json')
  ];

  for (const file of ocrCandidates) {
    if (fs.existsSync(file)) {
      try {
        const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
        const list = Array.isArray(raw) ? raw : (raw.comments || raw.findings || []);
        if (list.length > 0) {
          findings = list.map((c, i) => ({
            id: c.id || `QBIT-${i + 1}`,
            path: c.path || 'unknown',
            start_line: c.start_line || 1,
            end_line: c.end_line || c.start_line || 1,
            severity: (c.severity || 'medium').toLowerCase(),
            category: c.category || 'security',
            cwe_id: c.cwe_id,
            content: c.content || c.description || 'Defect detected',
            existing_code: c.existing_code,
            suggestion_code: c.suggestion_code || c.suggestion,
            patch_description: c.patch_description || c.remediation,
            status: c.status || 'open'
          }));
          console.log(chalk.blue(`  ✔ Loaded ${findings.length} findings from ${path.basename(file)}`));
          break;
        }
      } catch {}
    }
  }

  // Fallback to fresh scan only if no report file exists
  if (findings.length === 0) {
    try {
      console.log(chalk.dim('No cached ocr_output.json found in current directory. Running quick scan...'));
      const scanRes = await runScan({ targetDir });
      if (scanRes.status === 'error') {
        console.error(chalk.red.bold(`\n✖ Could not fetch findings: ${scanRes.error}`));
        process.exit(1);
      }
      findings = scanRes.findings || [];
    } catch (err) {
      console.error(chalk.red.bold(`\n✖ Error during scan: ${err.message}`));
      process.exit(1);
    }
  }

  if (findings.length === 0) {
    console.log(chalk.green('\n✔ No vulnerabilities detected to fix.\n'));
    return;
  }

  printFindingsTable(findings);

  let targets = [];

  if (options.all) {
    targets = findings;
  } else if (options.id) {
    const rawId = options.id.toString().trim();
    const matched = findings.find(f => f.id.toLowerCase() === rawId.toLowerCase()) 
      || findings.find(f => f.id.toLowerCase() === `qbit-${rawId}`.toLowerCase())
      || (Number.isInteger(parseInt(rawId, 10)) ? findings[parseInt(rawId, 10) - 1] : null);
    if (matched) {
      targets = [matched];
    } else {
      console.log(chalk.red(`Invalid finding ID: ${options.id}`));
      return;
    }
  } else {
    // Interactive selection via readline
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    try {
      const answer = await rl.question(
        chalk.bold(`\nEnter finding number(s) to fix (e.g. 1, 2 or 'all'): `)
      );
      const trimmed = answer.trim().toLowerCase();
      if (trimmed === 'all') {
        targets = findings;
      } else if (trimmed) {
        const parts = trimmed.split(/[\s,]+/).map(p => parseInt(p, 10) - 1);
        targets = parts.map(i => findings[i]).filter(Boolean);
      }
    } finally {
      rl.close();
    }
  }

  if (targets.length === 0) {
    console.log(chalk.yellow('No findings selected for remediation. Exiting.'));
    return;
  }

  console.log(chalk.green.bold(`\nApplying fixes for ${targets.length} finding(s)...`));

  for (const finding of targets) {
    console.log(chalk.cyan(`\n▶ Fixing [${finding.id}] ${finding.path}:${finding.start_line}...`));
    console.log(chalk.dim(`  Issue: ${finding.content}`));

    // Create a descriptive git branch for this fix if inside a git repository
    let branchCreated = false;
    const branchName = `fix/${finding.id.toLowerCase()}-${(finding.cwe_id || finding.category || 'vulnerability').toLowerCase().replace(/[^a-z0-9_-]/g, '_')}`;
    try {
      const { execSync } = await import('node:child_process');
      const isGit = execSync('git rev-parse --is-inside-work-tree 2>/dev/null', { encoding: 'utf8' }).trim() === 'true';
      if (isGit) {
        execSync(`git checkout -b "${branchName}" 2>/dev/null || git checkout "${branchName}" 2>/dev/null`, { stdio: 'ignore' });
        branchCreated = true;
        console.log(chalk.blue(`  🌿 Switched to branch: ${branchName}`));
      }
    } catch {}

    const result = await applyFixWithOpenCode({
      finding,
      onLog: (msg) => {
        process.stdout.write(chalk.dim(`    ${msg}\n`));
      }
    });

    if (result.success) {
      console.log(chalk.green.bold(`  ✔ Successfully updated ${finding.path} (${result.mode})`));
      try {
        const { ScanCache } = await import('../core/scan-cache.js');
        const cache = new ScanCache(process.cwd());
        cache.markFixed(finding.id);
      } catch {}
      // Stage and commit the fix
      try {
        const { execSync } = await import('node:child_process');
        execSync(`git add "${finding.path}"`, { stdio: 'ignore' });
        const commitMsg = `fix(${finding.id}): resolve ${finding.cwe_id || finding.category} in ${finding.path}:${finding.start_line}\n\n${finding.content}`;
        execSync(`git commit -m "${commitMsg.replace(/"/g, '\\"')}"`, { stdio: 'ignore' });
        console.log(chalk.green(`  📦 Committed fix on branch ${branchName}`));
      } catch (cErr) {
        // If git commit fails (e.g. no change or git unconfigured), continue gracefully
      }
    } else {
      console.log(chalk.red.bold(`  ✖ Could not apply fix automatically: ${result.output}`));
    }
  }

  console.log(chalk.green.bold('\n✨ Remediation complete!'));
}
