import chalk from 'chalk';
import path from 'node:path';

export function formatSeverityBadge(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return chalk.bgRgb(220, 20, 60).white.bold(' ✖ CRITICAL ');
    case 'high':
      return chalk.bgRgb(255, 87, 34).white.bold(' ⚠ HIGH ');
    case 'medium':
      return chalk.bgRgb(255, 179, 0).black.bold(' ⚡ MEDIUM ');
    case 'low':
      return chalk.bgRgb(3, 169, 244).black.bold(' ℹ LOW ');
    default:
      return chalk.bgGray.white(' INFO ');
  }
}

export function formatCategoryBadge(category) {
  switch ((category || '').toLowerCase()) {
    case 'security':
      return chalk.magenta.bold('[SECURITY]');
    case 'bug':
      return chalk.redBright.bold('[DEFECT]');
    case 'maintainability':
      return chalk.cyanBright('[MAINTAINABILITY]');
    case 'performance':
      return chalk.greenBright('[PERFORMANCE]');
    default:
      return chalk.dim(`[${(category || 'OTHER').toUpperCase()}]`);
  }
}

export function formatCweBadge(cweId) {
  if (!cweId || cweId === 'NONE' || cweId === 'N/A') return '';
  return chalk.bgRgb(74, 20, 140).white.bold(` ${cweId} `);
}

export function formatCveBadge(cveId) {
  if (!cveId || cveId === 'N/A') return '';
  return chalk.bgRgb(180, 40, 40).white.bold(` REF ${cveId} `);
}

/**
 * Creates an OSC 8 terminal hyperlink if possible, with styled fallback
 */
function formatClickableLocation(filePath, line = 1) {
  const fullPath = path.isAbsolute(filePath) ? filePath : path.resolve(filePath);
  const label = `${filePath}:${line}`;
  // OSC 8 hyperlink format: ESC ] 8 ; ; url ESC \ text ESC ] 8 ; ; ESC \
  const osc8 = `\u001b]8;;file://${fullPath}\u0007${label}\u001b]8;;\u0007`;
  return chalk.cyan.underline(osc8);
}

export function printFindingsTable(findings = []) {
  if (!findings || findings.length === 0) {
    console.log(chalk.greenBright.bold('\n  ✔ No vulnerabilities or defects detected! Codebase is secure.\n'));
    return;
  }

  const border = chalk.hex('#0055ff')('─'.repeat(74));
  console.log(`\n${border}`);
  console.log(chalk.bold.hex('#00F0FF')(`  🛡️  QBIT VULNERABILITY AUDIT REPORT (${findings.length} Finding${findings.length === 1 ? '' : 's'})`));
  console.log(chalk.dim('     CWE / CVE references are provided for external attribution.'));
  console.log(`${border}\n`);

  findings.forEach((f, idx) => {
    const idStr = f.id || `QBIT-${idx + 1}`;
    const idBadge = chalk.bold.hex('#00FFFF')(`[${idStr}]`);
    const sevBadge = formatSeverityBadge(f.severity);
    const catBadge = formatCategoryBadge(f.category);
    const cweBadge = formatCweBadge(f.cwe_id);
    const cveBadge = formatCveBadge(f.cve_id);
    const loc = formatClickableLocation(f.path, f.start_line);

    const refChips = [cweBadge, cveBadge].filter(Boolean).join(' ');

    console.log(`  ${idBadge} ${sevBadge} ${catBadge} ${refChips ? refChips + ' ' : ''}${loc}`);
    console.log(`      ${chalk.white.bold(f.content)}`);

    if (f.cwe_title && f.cwe_title !== f.cwe_id) {
      console.log(`      ${chalk.dim('CWE Root Cause: ')}${chalk.hex('#B388FF')(f.cwe_title)}`);
    }

    if (f.existing_code) {
      const codeSnippet = f.existing_code.trim().split('\n').slice(0, 2).join('\n      ');
      console.log(`      ${chalk.dim('Vulnerable: ')}${chalk.redBright(codeSnippet)}`);
    }

    if (f.suggestion_code) {
      const suggSnippet = f.suggestion_code.trim().split('\n').slice(0, 2).join('\n      ');
      console.log(`      ${chalk.dim('Suggestion: ')}${chalk.greenBright(suggSnippet)}`);
    }

    console.log(`      ${chalk.dim('Quick Remediation:')} ${chalk.bold.hex('#00FFCC')(`/fix ${idStr}`)}\n`);
  });

  console.log(`${border}`);
  console.log(chalk.hex('#FFD700').bold('  ⚡ TO FIX ANY FINDING WITH THE AUTONOMOUS AGENT:'));
  console.log(chalk.white(`     Type in the prompt: `) + chalk.cyan.bold('/fix <ID>') + chalk.dim(' (e.g. ') + chalk.bold.hex('#00F0FF')('/fix QBIT-1') + chalk.dim(')'));
  console.log(chalk.dim(`     Autocomplete is active: typing `) + chalk.cyan('/fix ') + chalk.dim(`displays the interactive list of all findings.`));
  console.log(`${border}\n`);
}
