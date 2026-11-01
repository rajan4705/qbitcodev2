import fs from 'node:fs';
import path from 'node:path';
import chalk from 'chalk';
import { runScan, runReview } from '../core/ocr-runner.js';
import { runSubrepoBatchScan, discoverSubRepositories } from '../core/subrepo-runner.js';
import { normalizeFinding } from '../core/types.js';
import { enrichFindings } from '../core/cve-enricher.js';
import { synthesizeAllPatches } from '../core/patch-synthesizer.js';
import { generateFindingsCsv } from '../core/csv-exporter.js';
import { formatSeverityBadge, formatCategoryBadge, formatCweBadge, formatCveBadge, printFindingsTable } from './formatters.js';
import { analyzeExemptions, saveExemptions, loadExemptions, formatExemptionsReport } from '../core/scan-exemptions.js';

function formatTqdmBar(current, total, elapsedMs) {
  const percent = total > 0 ? Math.min(100, Math.round((current / total) * 100)) : 0;
  const barWidth = 28;
  const filled = total > 0 ? Math.min(barWidth, Math.round((barWidth * current) / total)) : 0;
  const empty = Math.max(0, barWidth - filled);

  const bar = chalk.cyan('█'.repeat(filled)) + chalk.dim('░'.repeat(empty));

  const elapsedSec = Math.max(0.1, (elapsedMs / 1000));
  const rate = (current / elapsedSec).toFixed(1);
  const remainingSec = parseFloat(rate) > 0 && total > current
    ? Math.round((total - current) / parseFloat(rate))
    : 0;

  const fmtTime = (s) => {
    const mins = String(Math.floor(s / 60)).padStart(2, '0');
    const secs = String(Math.floor(s % 60)).padStart(2, '0');
    return `${mins}:${secs}`;
  };

  const timerStr = `[${fmtTime(Math.floor(elapsedSec))}<${fmtTime(remainingSec)}, ${rate}files/s]`;
  const pctStr = String(percent).padStart(3, ' ') + '%';
  const countStr = `${current}/${total || '?'}`;

  return `\r${pctStr}|${bar}| ${countStr} ${chalk.dim(timerStr)}`;
}

export async function handleFastScan(targetPath, options = {}) {
  const target = options.path || targetPath || process.cwd();
  const format = options.format || 'text';
  const analysis = analyzeExemptions(target);

  // Save exemptions to .qbit/scan_exemptions.json and .scanignore
  saveExemptions(target, analysis);

  if (format === 'json') {
    console.log(JSON.stringify(analysis, null, 2));
  } else {
    console.log(formatExemptionsReport(analysis));
  }

  if (options.runScan) {
    console.log(chalk.cyan.bold('\n🚀 Triggering fast scan with configured exemptions...\n'));
    return handleScan(targetPath, { ...options, exclude: analysis.excludeArgsString });
  }

  return analysis;
}

export async function handleScan(targetPath, options = {}) {
  const pathFilter = options.path || targetPath || '';
  const format = (options.format || 'text').toLowerCase();
  const defaultOutputFile = format === 'csv'
    ? path.join(process.cwd(), 'vulnerabilities.csv')
    : path.join(process.cwd(), 'ocr_output.json');
  const outputFile = options.output || defaultOutputFile;
  const includePatches = options.patches !== false && options.patches !== 'false';
  const shouldEnrich = options.enrich !== false && options.enrich !== 'false';
  const minSeverity = options.minSeverity || 'high';

  // Resolve exclusion patterns: explicit CLI option, or auto-load from saved exemptions
  let exclude = options.exclude || '';
  if (!exclude) {
    const savedExemptions = loadExemptions(process.cwd());
    if (savedExemptions && savedExemptions.excludeArgsString) {
      exclude = savedExemptions.excludeArgsString;
      if (format === 'text') {
        console.log(chalk.yellow(`⚡ [FASTSCAN ACTIVE] Applied ${savedExemptions.excludePatterns.length} exclusions (${savedExemptions.summary?.exemptFoldersCount || 0} folders, ${savedExemptions.summary?.exemptFilesCount || 0} files exempted).`));
      }
    }
  } else if (format === 'text') {
    console.log(chalk.yellow(`⚡ [EXCLUDE] Custom exclude patterns active: ${exclude}`));
  }

  // Check if target workspace contains multiple sub-repositories (multi-repo mode)
  if (!pathFilter) {
    const subrepos = discoverSubRepositories(process.cwd());
    if (subrepos.length > 1) {
      console.log(chalk.cyan.bold(`\n🚀 [MULTI-REPO MODE] Detected ${subrepos.length} distinct sub-repositories.`));
      console.log(chalk.dim(`   Executing granular sub-repo scans with single shared root .qbit/ cache...\n`));
      
      const batchResult = await runSubrepoBatchScan({
        workspaceRoot: process.cwd(),
        exclude,
        minSeverity,
        onProgress: (msg) => {
          process.stdout.write(msg);
        }
      });

      if (batchResult.status === 'success') {
        console.log(chalk.green.bold('\n✔ Multi-repository scan batch completed successfully!'));
        let finalFindings = batchResult.findings || [];

        // Filter minSeverity if requested
        if (minSeverity === 'high' || minSeverity === 'critical') {
          finalFindings = finalFindings.filter(f => f.severity === 'critical' || f.severity === 'high');
        }

        // Enrich findings with reference CWE-ID & CVE-ID from localhost:8080
        if (shouldEnrich && finalFindings.length > 0) {
          process.stdout.write(chalk.dim('\n⏳ Enriching findings with MITRE CWE & CVE attributions...\n'));
          await enrichFindings(finalFindings, { timeoutMs: 2000 });
        }

        // Synthesize full inline patches if requested
        if (includePatches && finalFindings.length > 0) {
          process.stdout.write(chalk.dim('⚡ Synthesizing verified inline code patches...\n'));
          await synthesizeAllPatches(finalFindings, process.cwd(), (current, total) => {
            process.stdout.write(`\r   [Patch Synthesizer] Generated ${current}/${total} patches...`);
          });
          process.stdout.write('\n');
        }

        if (format === 'csv') {
          const csvData = generateFindingsCsv(finalFindings, { includePatches });
          fs.writeFileSync(outputFile, csvData, 'utf8');
          console.log(chalk.green.bold(`\n📊 Exported ${finalFindings.length} findings to CSV: ${outputFile}\n`));
        } else if (format === 'json') {
          const jsonStr = JSON.stringify({
            status: 'success',
            total: finalFindings.length,
            findings: finalFindings
          }, null, 2);
          fs.writeFileSync(outputFile, jsonStr, 'utf8');
          console.log(chalk.green.bold(`\n📄 Exported findings to JSON: ${outputFile}\n`));
        } else {
          printFindingsTable(finalFindings);
        }
      }
      return batchResult;
    }
  }

  if (format === 'text') {
    console.log(chalk.cyan.bold('\n🔍 Running Qbit Vulnerability Scan...'));
    console.log(chalk.dim(`   Target: ${pathFilter || 'Current Workspace'}\n`));
  }

  const startTime = Date.now();
  let totalFiles = 0;
  let reviewedFiles = 0;
  let streamedFindings = 0;

  const onProgress = (chunk, tmpFile) => {
    if (format !== 'text') return;

    // Detect total files from OCR discovery lines
    const totalMatch = chunk.match(/reviewing (\d+) in/) || chunk.match(/(\d+) file\(s\) discovered/);
    if (totalMatch) {
      totalFiles = parseInt(totalMatch[1], 10);
    }

    // Increment reviewed files on code_comment completions
    const commentMatches = (chunk.match(/✔ code_comment/g) || []).length;
    if (commentMatches > 0) {
      reviewedFiles = Math.min(totalFiles || 999, reviewedFiles + commentMatches);
    }

    // Check intermediate output file for new findings
    if (tmpFile && fs.existsSync(tmpFile)) {
      try {
        const content = fs.readFileSync(tmpFile, 'utf8');
        const partial = JSON.parse(content);
        if (partial.comments && partial.comments.length > streamedFindings) {
          const newComments = partial.comments.slice(streamedFindings);
          for (let i = 0; i < newComments.length; i++) {
            const raw = newComments[i];
            const finding = normalizeFinding(raw, streamedFindings + i + 1);

            // Clear current tqdm line
            process.stdout.write('\r\x1b[K');
            const num = chalk.bold(`[#${streamedFindings + i + 1}]`);
            const sev = formatSeverityBadge(finding.severity);
            const cat = formatCategoryBadge(finding.category);
            const loc = chalk.bold.white(`${finding.path}:${finding.start_line}`);

            console.log(`  ${chalk.yellow('⚡')} ${num} ${sev} ${cat} ${loc}`);
            console.log(`     ${chalk.italic(finding.content.split('\n')[0])}`);
            if (finding.existing_code) {
              console.log(`     ${chalk.dim('Code: ')}${chalk.red(finding.existing_code.trim().split('\n')[0])}`);
            }
            console.log();
          }
          streamedFindings = partial.comments.length;
        }
      } catch {}
    }

    // Render tqdm progress bar
    if (totalFiles > 0) {
      process.stdout.write(formatTqdmBar(reviewedFiles, totalFiles, Date.now() - startTime));
    }
  };

  try {
    const result = await runScan({
      pathFilter,
      exclude,
      format,
      outputFile,
      onProgress,
      noResume: options.resume === false,
      noCache: options.cache === false
    });

    if (result.status === 'error') {
      process.stdout.write('\r\x1b[K');
      console.error(chalk.red.bold(`\n✖ Scan failed: ${result.error}`));
      process.exit(1);
    }

    if (result.status === 'interrupted') {
      process.stdout.write('\r\x1b[K');
      console.log(chalk.yellow.bold(`\n⚠️  Scan interrupted or crashed (${result.completedFiles?.length || 0} file(s) completed before stop).`));
      if (result.sessionId) {
        console.log(chalk.dim(`   Session ID: ${result.sessionId}`));
      }
      console.log(chalk.yellow(`   Rescued: ${result.findings?.length || 0} finding(s) saved to cache & ocr_output.json.`));
      console.log(chalk.cyan(`   💡 Run '${chalk.bold('qbit scan')}' again to automatically resume from where it stopped.\n`));

      if (result.findings && result.findings.length > 0) {
        if (format === 'text') {
          process.stdout.write(chalk.dim('⏳ Fetching reference MITRE CWE & CVE attributions...\r'));
        }
        await enrichFindings(result.findings);
      }

      const jsonStr = JSON.stringify({
        status: 'interrupted',
        sessionId: result.sessionId,
        completedFiles: result.completedFiles,
        summary: result.summary,
        comments: result.findings
      }, null, 2);
      try {
        fs.writeFileSync(outputFile, jsonStr, 'utf8');
      } catch {}

      if (format === 'json') {
        console.log(jsonStr);
      } else {
        const relOut = path.relative(process.cwd(), outputFile) || 'ocr_output.json';
        console.log(chalk.dim(`Partial results saved to ${relOut}\n`));
      }

      return result.findings;
    }

    // Enrich findings with reference CWE-ID & CVE-ID from localhost:8080 (for display/reference only)
    if (shouldEnrich && result.findings && result.findings.length > 0) {
      if (format === 'text') {
        process.stdout.write('\r\x1b[K');
        process.stdout.write(chalk.dim('⏳ Fetching reference MITRE CWE & CVE attributions...\r'));
      }
      await enrichFindings(result.findings, { timeoutMs: 2000 });
    }

    // Synthesize code patches if requested
    if (includePatches && result.findings && result.findings.length > 0) {
      if (format === 'text') {
        process.stdout.write('\r\x1b[K');
        process.stdout.write(chalk.dim('⚡ Synthesizing verified inline code patches...\n'));
      }
      await synthesizeAllPatches(result.findings, process.cwd(), (current, total) => {
        if (format === 'text') {
          process.stdout.write(`\r   [Patch Synthesizer] Generated ${current}/${total} patches...`);
        }
      });
      if (format === 'text') process.stdout.write('\n');
    }

    if (format === 'csv') {
      const csvData = generateFindingsCsv(result.findings || [], { includePatches });
      fs.writeFileSync(outputFile, csvData, 'utf8');
      console.log(chalk.green.bold(`\n📊 Exported ${result.findings?.length || 0} findings to CSV: ${outputFile}\n`));
      return result.findings;
    }

    // Save results to outputFile (defaults to ocr_output.json in cwd)
    const jsonStr = JSON.stringify({
      status: 'success',
      summary: result.summary,
      comments: result.findings
    }, null, 2);
    try {
      fs.writeFileSync(outputFile, jsonStr, 'utf8');
    } catch {}

    if (format === 'json') {
      console.log(jsonStr);
    } else {
      process.stdout.write('\r\x1b[K');
      if (totalFiles > 0) {
        console.log(formatTqdmBar(totalFiles, totalFiles, Date.now() - startTime));
      }
      console.log();
      const relOut = path.relative(process.cwd(), outputFile) || 'ocr_output.json';
      console.log(chalk.dim(`Results saved to ${relOut}\n`));
    }

    return result.findings;
  } catch (err) {
    process.stdout.write('\r\x1b[K');
    console.error(chalk.red.bold(`\n✖ Scan error: ${err.message}`));
    process.exit(1);
  }
}

export async function handleReview(options = {}) {
  const format = options.format || 'text';
  const outputFile = options.output || '';

  if (format === 'text') {
    console.log(chalk.cyan.bold('\n🔎 Running Qbit Git Diff Review...'));
    console.log(chalk.dim(`   Mode: ${options.staged ? 'Staged Changes' : 'Working Tree Diff'}`));
  }

  try {
    const result = await runReview({
      staged: options.staged,
      from: options.from,
      to: options.to,
      commit: options.commit,
      format,
      outputFile
    });

    if (result.status === 'error') {
      console.error(chalk.red.bold(`\n✖ Review failed: ${result.error}`));
      process.exit(1);
    }

    if (format === 'json') {
      const jsonStr = JSON.stringify(result.findings, null, 2);
      if (outputFile) {
        fs.writeFileSync(outputFile, jsonStr, 'utf8');
        console.log(`Results written to ${outputFile}`);
      } else {
        console.log(jsonStr);
      }
    } else {
      printFindingsTable(result.findings);
    }

    return result.findings;
  } catch (err) {
    console.error(chalk.red.bold(`\n✖ Review error: ${err.message}`));
    process.exit(1);
  }
}
