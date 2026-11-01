import { discoverSubRepositories } from '../qbit-code-reviewer/src/core/subrepo-runner.js';
import { ScanCache } from '../qbit-code-reviewer/src/core/scan-cache.js';
import assert from 'node:assert';
import path from 'node:path';

async function runTest() {
  console.log('🧪 Starting Sub-Repository Discovery & Upfront Cache Architecture Test...');

  const mockSoftwareRoot = '/home/minakshi.katoch/Desktop/Mock_Data/Software';

  console.log('1. Discovering and ordering sub-repositories...');
  const subrepos = discoverSubRepositories(mockSoftwareRoot);
  assert(subrepos.length > 0, 'Must discover sub-repositories in Mock_Data/Software');
  console.log(`✓ Discovered ${subrepos.length} distinct sub-repositories.`);

  console.log('2. Verifying Baseline Priority Order (Stack 1 first)...');
  const first6 = subrepos.slice(0, 6);
  for (const s of first6) {
    assert(s.isBaseline, `First subrepos must be baseline Stack 1, got: ${s.name}`);
  }
  console.log(`✓ Confirmed: All Stack 1 baselines are prioritized first:`);
  first6.forEach(s => console.log(`   - ${s.name}`));

  console.log('3. Verifying Single Root Cache Storage (.qbit/ at workspaceRoot)...');
  const cache = new ScanCache(mockSoftwareRoot);
  assert.strictEqual(cache.cacheDir, path.join(mockSoftwareRoot, '.qbit'), 'Cache must reside ONLY in root .qbit');
  console.log(`✓ Confirmed: Single central cache at ${cache.cacheDir}`);

  console.log('\n🎉 ALL ARCHITECTURE CHECKS PASSED! Sub-repo batching and central caching are validated.');
}

runTest().catch(err => {
  console.error('❌ Sub-repo test failed:', err);
  process.exit(1);
});

