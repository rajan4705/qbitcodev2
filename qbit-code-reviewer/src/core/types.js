import fs from 'node:fs';
import path from 'node:path';

/**
 * Normalizes an OCR comment into a standard Qbit Finding object.
 */
export function normalizeFinding(rawComment, index = 1) {
  const category = (rawComment.category || 'security').toLowerCase();
  let severity = (rawComment.severity || rawComment.Severity || 'medium').toLowerCase();

  // If category is security and severity not critical, boost if keywords present
  const content = rawComment.content || rawComment.Vulnerability || rawComment.message || 'No description provided';
  if (category === 'security' && (content.toLowerCase().includes('overflow') || content.toLowerCase().includes('injection'))) {
    severity = 'high';
  }

  const rawPath = rawComment.path || rawComment.file || rawComment['filename with path'] || 'unknown';
  let startLine = 1;
  let endLine = 1;

  const rawLine = rawComment.start_line || rawComment.line || rawComment['line number'];
  if (typeof rawLine === 'string' && rawLine.includes(',')) {
    const parts = rawLine.split(',').map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p));
    if (parts.length > 0) startLine = parts[0];
    if (parts.length > 1) endLine = parts[parts.length - 1];
    else endLine = startLine;
  } else {
    startLine = parseInt(rawComment.start_line || rawComment.line || rawComment['line number'] || 1, 10);
    if (isNaN(startLine) || startLine < 1) startLine = 1;
    endLine = parseInt(rawComment.end_line || startLine, 10);
    if (isNaN(endLine) || endLine < startLine) endLine = startLine;
  }

  let existing_code = rawComment.existing_code || rawComment.code || rawComment['Code Snippet at the line'] || '';
  if (!existing_code && rawPath && rawPath !== 'unknown') {
    try {
      const targetPath = path.isAbsolute(rawPath) ? rawPath : path.join(process.cwd(), rawPath);
      if (fs.existsSync(targetPath)) {
        const fileContent = fs.readFileSync(targetPath, 'utf8');
        const lines = fileContent.split('\n');
        const start = Math.max(0, startLine - 1);
        const end = Math.min(lines.length, Math.max(start + 1, endLine + 1));
        existing_code = lines.slice(start, end).join('\n');
      }
    } catch {}
  }

  const suggestion_code = rawComment.suggestion_code || rawComment.Patch || rawComment.suggestion || rawComment.patch || '';
  const patch_description = rawComment.patch_description || rawComment['Patch Description'] || '';

  return {
    id: rawComment.id || `QBIT-${index}`,
    path: rawPath,
    start_line: startLine,
    end_line: endLine,
    category: category,
    severity: severity,
    content: content,
    existing_code: existing_code,
    suggestion_code: suggestion_code,
    patch_description: patch_description,
    status: rawComment.status || 'open', // open, fixing, fixed, ignored
    cwe_id: rawComment.cwe_id || rawComment['Common Weakness Enumeration (CWE) Id'] || undefined,
    cwe_title: rawComment.cwe_title || undefined,
    cve_id: rawComment.cve_id || rawComment['CVE ID'] || undefined,
    ref_cwe_id: rawComment.ref_cwe_id || undefined,
    ref_cve_id: rawComment.ref_cve_id || rawComment.closest_reference_cve || undefined,
    source: rawComment.source || (rawComment.id && rawComment.id.startsWith('SCA-') ? 'sca' : 'ast'),
    nvd_severity: rawComment.nvd_severity || undefined,
    created_at: rawComment.created_at || new Date().toISOString()
  };
}

/**
 * Summarizes findings collection into counts
 */
export function summarizeFindings(findings = []) {
  const summary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    categories: {
      security: 0,
      bug: 0,
      maintainability: 0,
      style: 0,
      performance: 0
    },
    status: {
      open: 0,
      fixing: 0,
      fixed: 0,
      ignored: 0
    }
  };

  for (const f of findings) {
    if (summary[f.severity] !== undefined) summary[f.severity]++;
    if (summary.categories[f.category] !== undefined) summary.categories[f.category]++;
    if (summary.status[f.status] !== undefined) summary.status[f.status]++;
  }

  return summary;
}
