import path from 'node:path';
import { isConcretePatch } from './patch-synthesizer.js';

/**
 * Maps file extension to benchmark language name
 */
export function getBenchmarkLanguage(filepath = '') {
  if (!filepath) return 'C';
  const ext = filepath.split('.').pop()?.toLowerCase() || '';
  switch (ext) {
    case 'c':
    case 'h':
      return 'C';
    case 'cpp':
    case 'cc':
    case 'cxx':
    case 'hpp':
      return 'C++';
    case 'py':
      return 'Python';
    case 'js':
    case 'jsx':
    case 'mjs':
    case 'cjs':
      return 'JavaScript';
    case 'ts':
    case 'tsx':
      return 'TypeScript';
    case 'java':
      return 'Java';
    case 'go':
      return 'Go';
    case 'rs':
      return 'Rust';
    case 'php':
      return 'PHP';
    case 'rb':
      return 'Ruby';
    case 'cs':
      return 'C#';
    default:
      return 'C';
  }
}

/**
 * Escapes values in RFC 4180 standard CSV format
 */
export function escapeCsv(val) {
  if (val === null || val === undefined) return '""';
  const str = String(val).replace(/"/g, '""');
  return `"${str}"`;
}

/**
 * Formats line number range
 */
export function formatLineNumber(start, end) {
  if (!start) return '1';
  if (!end || start === end) return String(start);
  return `${start}-${end}`;
}

/**
 * Resolves repository name from finding path or workspace
 */
export function extractRepoName(findingPath = '', workspaceRoot = '') {
  const normalized = findingPath.replace(/\\/g, '/');
  // Check if finding path starts with common multi-repo parent folder (e.g. testing repos/xyz or repos/xyz)
  const parts = normalized.split('/').filter(Boolean);
  if (parts.length > 1 && (parts[0] === 'testing repos' || parts[0] === 'repos' || parts[0] === 'ps1_mock2')) {
    return parts[1];
  }
  if (workspaceRoot) {
    return path.basename(workspaceRoot);
  }
  return parts.length > 1 ? parts[0] : 'repository';
}

/**
 * Generates CSV string for a list of findings with patches
 */
export function generateFindingsCsv(findings = [], options = {}) {
  const { includePatches = true, repoName = '' } = options;

  let headers = [
    'SNo',
    'Repository',
    'Primary Language of Benchmark',
    'Vulnerability',
    'CVE ID',
    'Severity',
    'Common Weakness Enumeration (CWE) Id',
    'Reference IDs',
    'filename with path',
    'line number',
    'Code Snippet at the line'
  ];

  if (includePatches) {
    headers.push('Patch', 'Patch Description');
  }

  const headerLine = headers.join(',');

  const rows = findings.map((f, i) => {
    const rName = repoName || f.repository || extractRepoName(f.path);
    const row = [
      i + 1,
      escapeCsv(rName),
      escapeCsv(getBenchmarkLanguage(f.path)),
      escapeCsv(f.content || ''),
      escapeCsv((f.cve_id && f.cve_id !== 'N/A') ? f.cve_id : (f.ref_cve_id && f.ref_cve_id !== 'N/A') ? f.ref_cve_id : 'N/A'),
      escapeCsv((f.severity || 'MEDIUM').toUpperCase()),
      escapeCsv((f.cwe_id && f.cwe_id !== 'N/A' && f.cwe_id !== 'NONE') ? f.cwe_id : (f.ref_cwe_id && f.ref_cwe_id !== 'N/A') ? f.ref_cwe_id : 'N/A'),
      escapeCsv(f.ref_cve_id || f.ref_cwe_id ? `${f.ref_cwe_id || ''} ${f.ref_cve_id || ''}`.trim() : 'N/A'),
      escapeCsv(f.path || ''),
      escapeCsv(formatLineNumber(f.start_line, f.end_line)),
      escapeCsv(f.existing_code || '')
    ];

    if (includePatches) {
      row.push(
        escapeCsv(f.suggestion_code || ''),
        escapeCsv(f.patch_description || `Remediation for ${f.cwe_id || f.category}: ${(f.content || '').slice(0, 150)}`)
      );
    }

    return row.join(',');
  });

  return [headerLine, ...rows].join('\n');
}

/**
 * Groups findings by repository name
 * @returns {Map<string, Array>} repoName -> findings[]
 */
export function groupFindingsByRepository(findings = [], workspaceRoot = '') {
  const groups = new Map();
  for (const f of findings) {
    const repo = f.repository || extractRepoName(f.path, workspaceRoot);
    if (!groups.has(repo)) {
      groups.set(repo, []);
    }
    groups.get(repo).push(f);
  }
  return groups;
}

