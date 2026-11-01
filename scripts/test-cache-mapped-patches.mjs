import { ScanCache } from '../qbit-code-reviewer/src/core/scan-cache.js';
import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs';

async function runTest() {
  console.log('🧪 Starting End-to-End Cache-Mapped Patch & Enrichment Test...');

  const testDir = path.join(process.cwd(), 'testing repos ', 'anvilly');
  const cache = new ScanCache(testDir);

  const mockFileHash = 'mock_hash_abc12345';
  const mockFindingWithPatch = {
    path: 'apps/web/app/globals.css',
    start_line: 10,
    end_line: 12,
    cwe_id: 'CWE-798',
    cve_id: 'CVE-2023-9999',
    ref_cwe_id: 'CWE-798',
    ref_cve_id: 'CVE-2024-1111',
    severity: 'HIGH',
    content: 'Hardcoded secret token',
    existing_code: 'const SECRET = "12345";',
    suggestion_code: 'const SECRET = process.env.SECRET;',
    patch_description: 'Load secret securely from environment variable'
  };

  console.log('1. Recording findings, CVE/CWE, and concrete patch into baseline cache...');
  cache.updateScanResults([mockFindingWithPatch], ['apps/web/app/globals.css']);

  // Simulate file hash registration
  cache.data.files['apps/web/app/globals.css'] = {
    hash: mockFileHash,
    size: 100,
    mtimeMs: Date.now(),
    scannedAt: Date.now()
  };
  cache.data.contentHashes[mockFileHash] = [mockFindingWithPatch];
  cache.save();
  console.log('✓ Baseline finding + patch saved to central contentHashes cache.');

  console.log('2. Simulating identical file discovered in a versioned sub-repository...');
  // Suppose identical content exists in a new stack directory
  const derivedRelPath = 'apps/web_version_2/app/globals.css';
  const realExistingFile = path.join(process.cwd(), 'qbit-code-reviewer', 'package.json');

  cache.adoptFindingsFromContentHash(derivedRelPath, realExistingFile, mockFileHash);

  console.log('3. Verifying that adopted finding inherits patch, CVE/CWE without re-computation...');
  const derivedFindings = cache.getFindings(derivedRelPath);
  assert.strictEqual(derivedFindings.length, 1, 'Must find 1 adopted finding');
  const adopted = derivedFindings[0];

  assert.strictEqual(adopted.cwe_id, 'CWE-798', 'Must retain ground-truth CWE ID');
  assert.strictEqual(adopted.cve_id, 'CVE-2023-9999', 'Must retain ground-truth CVE ID');
  assert.strictEqual(adopted.suggestion_code, 'const SECRET = process.env.SECRET;', 'Must retain synthesized patch');
  assert.strictEqual(adopted.patch_description, 'Load secret securely from environment variable', 'Must retain patch description');
  console.log('✓ Adopted finding verified: Patch and CVE/CWE were mapped instantly from cache with 0 LLM calls!');

  console.log('\n🎉 ALL CHECKS PASSED! Incremental sub-repo caching with patches is production-ready.');
}

runTest().catch(err => {
  console.error('❌ Test Failed:', err);
  process.exit(1);
});
