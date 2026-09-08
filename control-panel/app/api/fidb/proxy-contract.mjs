export const readRoutes = new Set([
  'health',
  'status',
  'snapshot',
  'events',
  'timings',
  'capabilities',
  'authority',
  'lane-inventory',
  'ecological-validation',
  'machine-validation',
  'machine-validation/run',
  'validation-observatory',
  'hash-discrimination',
  'hash-analysis-backend',
  'fid-matching-backend',
  'noisy-hashes',
  'retention',
  'export',
  'preflight',
]);

export const writeRoutes = new Set([
  'sync',
  'pause',
  'resume',
  'plan-drafts/resolve',
  'plan-drafts/save',
  'ecological-validation/import',
  'ecological-validation/run',
  'machine-validation/start',
  'machine-validation/pause',
  'machine-validation/resume',
  'noisy-hashes/decision',
  'hash-analysis-backend/mode',
  'fid-matching-backend/mode',
  'retention/plan',
  'retention/apply',
  'export/preview',
  'export/build',
]);

const queryKeys = new Map([
  ['events', new Set(['after', 'limit'])],
  ['timings', new Set(['limit'])],
  ['snapshot', new Set(['detail', 'include_inactive'])],
  ['validation-observatory', new Set(['run_id'])],
]);

export function validatedQuery(endpoint, requestUrl) {
  const allowed = queryKeys.get(endpoint) ?? new Set();
  for (const key of requestUrl.searchParams.keys()) {
    if (!allowed.has(key)) return null;
  }
  return requestUrl.search;
}
