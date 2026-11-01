import { ScanJobRegistry } from '../qbit-code-reviewer/src/server/scan-job-registry.js';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

async function runTest() {
  console.log('🧪 Starting Phase 2 Test: Background Scan Job Execution & SSH Decoupling...');
  
  const testWorkspace = path.join(process.cwd(), 'testing repos ', 'anvilly');
  const registry = new ScanJobRegistry(testWorkspace);

  console.log('1. Creating a background scan job...');
  const job = registry.createJob({
    pathFilter: '',
    exclude: '',
    fastMode: true,
    targetDir: testWorkspace
  });

  assert(job.id, 'Job must have a unique id');
  assert.strictEqual(job.status, 'pending');
  console.log(`✓ Job created successfully: ${job.id}`);

  console.log('2. Verifying disk persistence of pending job...');
  const jobFile = path.join(testWorkspace, '.qbit', 'jobs', `${job.id}.json`);
  assert(fs.existsSync(jobFile), 'Job state file must be written to disk');
  const diskData = JSON.parse(fs.readFileSync(jobFile, 'utf8'));
  assert.strictEqual(diskData.id, job.id);
  console.log(`✓ Job verified on disk at ${jobFile}`);

  console.log('3. Simulating HTTP SSE client attaching to job...');
  let eventCount = 0;
  const mockReq = { on: (evt, cb) => {} };
  const mockRes = {
    setHeader: () => {},
    write: (chunk) => {
      eventCount++;
    },
    end: () => {}
  };

  registry.attachSSE(job.id, mockRes, mockReq);
  assert(eventCount > 0, 'Reconnecting client must immediately receive initial status payload');
  console.log(`✓ Client attached and received ${eventCount} buffered events.`);

  console.log('4. Simulating client disconnect (e.g. SSH disconnect)...');
  mockRes.write = () => {
    throw new Error('Broken pipe: client disconnected');
  };

  // Emit event to job while client is broken
  registry.emitToJob(job, 'log', { message: 'Background processing file 1' });
  registry.emitToJob(job, 'log', { message: 'Background processing file 2' });

  assert.strictEqual(job.logs.length, 2, 'Job must buffer logs even if client is disconnected');
  console.log('✓ Logs successfully buffered in background job memory during client disconnect.');

  console.log('5. Simulating second client reconnecting after SSH re-established...');
  let reconnectedEvents = 0;
  const mockRes2 = {
    setHeader: () => {},
    write: (chunk) => {
      reconnectedEvents++;
    },
    end: () => {}
  };
  registry.attachSSE(job.id, mockRes2, mockReq);
  assert(reconnectedEvents >= 3, 'Reconnected client must receive replay of buffered logs');
  console.log(`✓ Reconnected client caught up with ${reconnectedEvents} buffered events!`);

  // Clean up test job file
  try { fs.unlinkSync(jobFile); } catch {}

  console.log('\n🎉 ALL PHASE 2 TESTS PASSED! Scan execution is completely decoupled from SSH connections.');
}

runTest().catch(err => {
  console.error('❌ Phase 2 Test Failed:', err);
  process.exit(1);
});
