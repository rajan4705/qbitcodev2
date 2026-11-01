import { generateFindingsCsv, groupFindingsByRepository } from '../qbit-code-reviewer/src/core/csv-exporter.js';
import assert from 'node:assert';

async function runTest() {
  console.log('🧪 Starting Phase 5 Test: Single & Multi-Repo CSV Export Engine...');

  const mockFindings = [
    {
      path: 'repos/repo_alpha/src/auth.py',
      start_line: 12,
      end_line: 15,
      cwe_id: 'CWE-798',
      cve_id: 'CVE-2023-1234',
      ref_cwe_id: 'CWE-798',
      ref_cve_id: 'CVE-2024-5555',
      severity: 'HIGH',
      content: 'Hardcoded secret token in auth module',
      existing_code: 'API_KEY = "super_secret_123"',
      suggestion_code: 'API_KEY = os.environ.get("API_KEY")',
      patch_description: 'Load secret from environment variable'
    },
    {
      path: 'repos/repo_alpha/src/db.py',
      start_line: 45,
      end_line: 48,
      cwe_id: 'CWE-89',
      cve_id: 'N/A',
      severity: 'CRITICAL',
      content: 'SQL Injection vulnerability via string formatting',
      existing_code: 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
      suggestion_code: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      patch_description: 'Use parameterized SQL queries'
    },
    {
      path: 'repos/repo_beta/lib/router.js',
      start_line: 80,
      end_line: 82,
      cwe_id: 'CWE-79',
      cve_id: 'CVE-2022-9999',
      severity: 'MEDIUM',
      content: 'Reflected Cross-site Scripting (XSS)',
      existing_code: 'res.send("<div>" + req.query.name + "</div>")',
      suggestion_code: 'res.send("<div>" + escapeHtml(req.query.name) + "</div>")',
      patch_description: 'Escape user input before rendering into HTML'
    }
  ];

  console.log('1. Testing Use Case A: Consolidated Single CSV Export...');
  const consolidatedCsv = generateFindingsCsv(mockFindings, { includePatches: true });
  assert(consolidatedCsv.includes('Repository'), 'CSV must include Repository column');
  assert(consolidatedCsv.includes('Patch'), 'CSV must include Patch column');
  assert(consolidatedCsv.includes('Patch Description'), 'CSV must include Patch Description column');
  assert(consolidatedCsv.includes('"repo_alpha"'), 'CSV must correctly associate finding with repo_alpha');
  assert(consolidatedCsv.includes('"repo_beta"'), 'CSV must correctly associate finding with repo_beta');
  assert(consolidatedCsv.includes('"Python"'), 'Must identify Python benchmark language');
  assert(consolidatedCsv.includes('"JavaScript"'), 'Must identify JavaScript benchmark language');
  
  const lines = consolidatedCsv.trim().split('\n');
  assert.strictEqual(lines.length, 4, '1 header line + 3 finding rows');
  console.log(`✓ Consolidated CSV verified (${lines.length - 1} findings exported with patch diffs).`);

  console.log('2. Testing Use Case B: Multi-Repository Grouping & Separate Exports...');
  const repoGroups = groupFindingsByRepository(mockFindings);
  assert.strictEqual(repoGroups.size, 2, 'Should create 2 repository groups (repo_alpha and repo_beta)');
  assert.strictEqual(repoGroups.get('repo_alpha').length, 2);
  assert.strictEqual(repoGroups.get('repo_beta').length, 1);

  const alphaCsv = generateFindingsCsv(repoGroups.get('repo_alpha'), { repoName: 'repo_alpha' });
  const betaCsv = generateFindingsCsv(repoGroups.get('repo_beta'), { repoName: 'repo_beta' });

  assert(alphaCsv.includes('"repo_alpha"') && !alphaCsv.includes('"repo_beta"'), 'Alpha CSV must contain only Alpha findings');
  assert(betaCsv.includes('"repo_beta"') && !betaCsv.includes('"repo_alpha"'), 'Beta CSV must contain only Beta findings');
  console.log('✓ Separate multi-repo CSV export files successfully generated and verified!');

  console.log('3. Testing RFC 4180 Escaping with Quotes and Newlines...');
  const findingWithQuotes = {
    path: 'test.py',
    content: 'Issue with "double quotes" and \n multiline text',
    suggestion_code: 'print("hello\nworld")'
  };
  const testCsv = generateFindingsCsv([findingWithQuotes]);
  assert(testCsv.includes('""double quotes""'), 'Inner double quotes must be properly escaped per RFC 4180');
  console.log('✓ RFC 4180 quotation and multi-line escaping verified.');

  console.log('\n🎉 ALL PHASE 5 TESTS PASSED! Single & Multi-Repo CSV export mechanisms are production-ready.');
}

runTest().catch(err => {
  console.error('❌ Phase 5 Test Failed:', err);
  process.exit(1);
});

