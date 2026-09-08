import assert from 'node:assert/strict';
import test from 'node:test';

import {
  readRoutes,
  validatedQuery,
  writeRoutes,
} from '../app/api/fidb/proxy-contract.mjs';

test('proxy exposes every control-panel read route', () => {
  assert.deepEqual([...readRoutes].sort(), [
    'authority',
    'capabilities',
    'ecological-validation',
    'events',
    'export',
    'fid-matching-backend',
    'hash-analysis-backend',
    'hash-discrimination',
    'health',
    'lane-inventory',
    'machine-validation',
    'machine-validation/run',
    'noisy-hashes',
    'preflight',
    'retention',
    'snapshot',
    'status',
    'timings',
    'validation-observatory',
  ]);
});

test('proxy exposes every control-panel mutation route', () => {
  assert.deepEqual([...writeRoutes].sort(), [
    'ecological-validation/import',
    'ecological-validation/run',
    'export/build',
    'export/preview',
    'export/safeguard',
    'fid-matching-backend/mode',
    'hash-analysis-backend/mode',
    'machine-validation/pause',
    'machine-validation/resume',
    'machine-validation/start',
    'noisy-hashes/decision',
    'pause',
    'plan-drafts/resolve',
    'plan-drafts/save',
    'resume',
    'retention/apply',
    'retention/plan',
    'sync',
  ]);
});

test('validation observatory accepts only its optional run selector', () => {
  assert.equal(
    validatedQuery(
      'validation-observatory',
      new URL('http://panel/api/fidb/validation-observatory?run_id=c10%3Arun-1'),
    ),
    '?run_id=c10%3Arun-1',
  );
  assert.equal(
    validatedQuery(
      'validation-observatory',
      new URL('http://panel/api/fidb/validation-observatory?path=/etc/passwd'),
    ),
    null,
  );
});
