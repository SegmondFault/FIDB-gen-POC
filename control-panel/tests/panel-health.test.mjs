import assert from 'node:assert/strict';
import test from 'node:test';

import { settlePanelRead } from '../app/panel-health.mjs';

test('optional panel failure resolves as local evidence', async () => {
  const health = { status: 'ok', coordinator: { state: 'ready' } };
  const [working, failed] = await Promise.all([
    settlePanelRead('retention', async () => ({ state: 'ready' })),
    settlePanelRead('validation-observatory', async () => {
      throw new Error('observatory unavailable');
    }),
  ]);

  assert.equal(health.coordinator.state, 'ready');
  assert.deepEqual(working, {
    key: 'retention',
    value: { state: 'ready' },
    error: null,
  });
  assert.deepEqual(failed, {
    key: 'validation-observatory',
    value: null,
    error: 'observatory unavailable',
  });
});
