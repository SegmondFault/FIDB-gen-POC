'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

export type ConnectionState = 'connecting' | 'live' | 'stale' | 'offline';

export type CoordinatorCounts = Record<
  'blocked' | 'complete' | 'failed' | 'leased' | 'queued' | 'running',
  number
>;

export type CoordinatorBatch = {
  id: string;
  name: string;
  position: number;
  plan_path: string;
  plan_digest: string;
  matrices: string[] | null;
  active: boolean;
};

export type CoordinatorJob = {
  job_id: string;
  batch_id: string;
  batch_position: number;
  base_cell: string;
  position: number;
  state: keyof CoordinatorCounts;
  current_stage: string | null;
  leased_by: string | null;
  attempt_count: number;
  blockers: string[];
  result: Record<string, unknown> | null;
  error: string | null;
};

export type CoordinatorAttempt = {
  attempt_id: number;
  job_id: string;
  attempt_number: number;
  lease_generation: number;
  worker_id: string;
  state: 'leased' | 'running' | 'complete' | 'failed' | 'expired';
  started_at: string;
  lease_expires_at: number;
  ended_at: string | null;
  duration_ns: number | null;
  duration_source: 'coordinator-wall-clock' | null;
  error: string | null;
  queue_wait_duration_ns?: number | null;
  queue_wait_source?: 'coordinator-wall-clock' | null;
  queue_wait_basis?: string | null;
};

export type StageSpanState =
  | 'started'
  | 'completed'
  | 'failed'
  | 'skipped'
  | 'interrupted';

export type StageSpan = {
  stage_attempt_id: number;
  attempt_id: number;
  job_id: string;
  attempt_number: number;
  lease_generation: number;
  worker_id: string;
  sequence: number;
  stage: string;
  stage_attempt: number;
  state: StageSpanState;
  started_at: string;
  ended_at: string | null;
  duration_ns: number | null;
  duration_source: 'worker-monotonic' | 'coordinator-wall-clock' | null;
  wall_clock_regressed: boolean;
  details: Record<string, unknown> | null;
  metrics: Record<string, unknown> | null;
  error: string | null;
};

export type CoordinatorSnapshot = {
  schema_version: string;
  status: 'disarmed' | 'paused' | 'ready' | 'active' | 'idle';
  config_name: string | null;
  armed: boolean;
  paused: boolean;
  max_workers: number;
  active_workers: number;
  available_worker_slots: number;
  poll_seconds: number;
  lease_seconds: number;
  max_attempts: number;
  sync_generation: number;
  synced_at: string | null;
  counts: CoordinatorCounts;
  claimable: number;
  last_event_id: number;
  batches: CoordinatorBatch[];
  jobs: CoordinatorJob[];
  attempts?: CoordinatorAttempt[];
  stage_attempts?: StageSpan[];
  stage_attempts_total?: number;
  stage_attempts_truncated?: boolean;
};

export type TimingDistribution = {
  min: number;
  p50: number;
  p90: number;
  p95: number;
  max: number;
  mean: number;
};

export type StageTimingAggregate = {
  stage: string;
  sample_count: number;
  state_counts: Record<string, number>;
  duration_ns: TimingDistribution | null;
  duration_source?: 'worker-monotonic';
};

export type WorkflowTimingAggregate = {
  workflow: string;
  sample_count: number;
  state_counts: Record<string, number>;
  duration_ns: TimingDistribution | null;
  duration_source?: 'coordinator-wall-clock';
  queue_wait_duration_ns: TimingDistribution | null;
  queue_wait_source?: 'coordinator-wall-clock';
  queue_wait_basis?: string | null;
};

export type TimingEta = Record<string, unknown> & {
  sample_count?: number;
  confidence?: string;
  projected_completion_at?: string;
  remaining_duration_ns?: number;
  p50_remaining_duration_ns?: number;
  p90_remaining_duration_ns?: number;
};

export type TimingSnapshot = {
  schema_version: 'fidb-timings/v1' | string;
  generated_at: string;
  limit: number;
  aggregate_sample_limit: number;
  aggregates_truncated: boolean;
  sample_policy?: {
    stage_percentiles: string;
    workflow_percentiles: string;
    interrupted_spans: string;
    aggregate_selection: string;
    queue_wait_basis: string;
    service_rate: string;
  };
  sample_counts: {
    stage_spans: number;
    completed_stage_spans: number;
    completed_workflows: number;
  };
  throughput: {
    kind: 'successful-attempt-service-rate-proxy' | string;
    sample_count: number;
    basis: 'completed-successful-final-attempt-wall-clock' | string;
    scope: 'excludes-retries-queue-idle-and-worker-concurrency' | string;
    service_jobs_per_hour: number;
  } | null;
  eta: TimingEta | null;
  stages: StageTimingAggregate[];
  workflows: WorkflowTimingAggregate[];
  recent: StageSpan[];
};

export type CapabilityReadiness = {
  job_id: string;
  batch_id: string;
  job_state: string;
  kind: string;
  executor: string;
  library_local_eligible: boolean;
  readiness: string;
  reasons: string[];
};

export type ToolchainCapability = {
  id: string;
  family: string;
  version: string;
  variant: string;
  capabilities: string[];
  state: string;
  target: {
    machine: string;
    endianness: string;
    elf_class: number;
    cross_arch: string | null;
  };
};

export type FactoryCapabilities = {
  schema_version: string;
  detection_mode: 'read-only';
  host: {
    system: string;
    machine: string;
    logical_cpus: number | null;
    memory_bytes: number | null;
  };
  analysis: {
    ready: boolean;
    ghidra: { state: string; path: string | null; version?: string | null };
    java: { available: boolean; path: string | null; version: string | null };
    pyghidra: { available: boolean; version: string | null };
  };
  worker_pools: {
    'library-local': {
      cell_kinds: string[];
      source_executor: 'local';
      qemu_required: false;
      eligible_jobs: number;
      ready_now: number;
      runnable_with_pinned_acquisition: number;
      blocked: number;
      max_workers?: number;
      active_workers?: number;
      available_worker_slots?: number;
    };
  };
  active_job_readiness: CapabilityReadiness[];
  toolchains: {
    registry_path: string;
    managed_cache: string;
    managed_preparation: boolean | 'per-attempt-extraction';
    entries: ToolchainCapability[];
  };
};

export type CoordinatorEvent = {
  event_id: number;
  occurred_at: string;
  event_type: string;
  actor: string;
  batch_id: string | null;
  job_id: string | null;
  plan_digest: string | null;
  payload: Record<string, unknown>;
};

export type AuthorityRecipe = {
  id: string;
  kind: 'native' | 'source-library' | 'malware';
  mode: 'native' | 'source';
  name: string;
  version: string;
  url: string;
  sha256: string;
  build_adapter: string;
  authority_path: string;
  static_archives?: string[];
  library_path?: string;
  toolchain_family?: string;
  toolchain_variants?: string[];
};

export type AuthorityToolchain = {
  id: string;
  family: string;
  version: string;
  variant: string;
  machine: string;
  endianness: string;
  elf_class: number;
  archive_capable: boolean;
  source_capable: boolean;
  cross_arch: string | null;
  cross_bin_prefix: string | null;
};

export type AuthorityFactor = {
  id: string;
  stage: string;
  label: string;
  control: string;
  evidence: string;
  confidence: string;
  impact: string;
  coverage_action: string;
};

export type AuthorityFactorVariant = {
  id: string;
  factor: string;
  group: string;
  label: string;
  state: string;
  authority: string;
};

export type AuthorityPlan = {
  path: string;
  toml_sha256: string;
  name: string;
  policy: { max_cells: number; priority: string };
  coverage: { factor_variants: string[] };
  queue: { strategy: string; recipe_order: string[] };
  matrices: Array<Record<string, unknown>>;
  plan_digest: string;
  summary: Record<string, number>;
  inventory: {
    summary: Record<string, number>;
    cells: Record<string, { state: string; evidence: string[]; note: string }>;
  };
};

export type FactoryAuthority = {
  schema_version: 'fidb-authority-catalog/v1';
  authority_digest: string;
  recipes: AuthorityRecipe[];
  native: {
    routes: Array<Record<string, unknown> & { id: string }>;
    treatments: Array<Record<string, unknown> & { id: string }>;
    profiles: Record<string, string[]>;
    authority_path: string;
  };
  toolchains: AuthorityToolchain[];
  factors: AuthorityFactor[];
  factor_variants: AuthorityFactorVariant[];
  plans: AuthorityPlan[];
  sources: Record<string, string>;
};

export type PlanDraftResult = {
  schema_version: string;
  path?: string;
  toml_sha256: string;
  previous_sha256?: string | null;
  resolved: {
    plan_digest: string;
    summary: Record<string, number>;
    inventory: AuthorityPlan['inventory'];
  };
};

type Health = {
  status: 'ok';
  coordinator: { state: 'ready' | 'not-initialized' };
};

type EventPage = {
  events: CoordinatorEvent[];
  next_cursor: number;
  has_more: boolean;
};

type ApiErrorBody = { error?: { code?: string; message?: string } };

const maxEventHistory = 500;
const eventPageSize = 200;
const capabilityRefreshMilliseconds = 60_000;

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/fidb/${path}`, {
    cache: 'no-store',
    credentials: 'same-origin',
    ...init,
  });
  const document = (await response.json()) as T & ApiErrorBody;
  if (!response.ok) {
    throw new Error(document.error?.message ?? `Coordinator request failed (${response.status})`);
  }
  return document;
}

export function useFactoryApi(pollMilliseconds = 5000) {
  const [connection, setConnection] = useState<ConnectionState>('connecting');
  const [snapshot, setSnapshot] = useState<CoordinatorSnapshot | null>(null);
  const [capabilities, setCapabilities] = useState<FactoryCapabilities | null>(null);
  const [authority, setAuthority] = useState<FactoryAuthority | null>(null);
  const [events, setEvents] = useState<CoordinatorEvent[]>([]);
  const [timings, setTimings] = useState<TimingSnapshot | null>(null);
  const [timingsError, setTimingsError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const hasSuccessfulRead = useRef(false);
  const refreshInFlight = useRef(false);
  const eventCursor = useRef(0);
  const eventHistory = useRef<CoordinatorEvent[]>([]);
  const capabilityCache = useRef<FactoryCapabilities | null>(null);
  const authorityCache = useRef<FactoryAuthority | null>(null);
  const lastCapabilityRead = useRef(0);

  const resetEvents = useCallback(() => {
    eventCursor.current = 0;
    eventHistory.current = [];
    setEvents([]);
  }, []);

  const refreshEvents = useCallback(async (current: CoordinatorSnapshot) => {
    if (current.last_event_id === 0) {
      resetEvents();
      return;
    }

    let cursor = eventCursor.current;
    let history = eventHistory.current;
    if (cursor > current.last_event_id) {
      cursor = 0;
      history = [];
    }
    if (history.length === 0) {
      cursor = Math.max(0, current.last_event_id - maxEventHistory);
    }

    let pages = 0;
    while (cursor < current.last_event_id && pages < 4) {
      const page = await json<EventPage>(
        `events?after=${cursor}&limit=${eventPageSize}`,
      );
      if (page.next_cursor < cursor) {
        throw new Error('Coordinator event cursor moved backwards');
      }
      if (page.events.length) {
        const merged = new Map(history.map(event => [event.event_id, event]));
        for (const event of page.events) merged.set(event.event_id, event);
        history = [...merged.values()]
          .sort((left, right) => left.event_id - right.event_id)
          .slice(-maxEventHistory);
      }
      if (page.next_cursor === cursor) break;
      cursor = page.next_cursor;
      pages += 1;
      if (!page.has_more) break;
    }

    eventCursor.current = cursor;
    eventHistory.current = history;
    setEvents(history);
  }, [resetEvents]);

  const refresh = useCallback(async (forceCapabilities = false) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    try {
      const health = await json<Health>('health');
      if (
        forceCapabilities
        || capabilityCache.current === null
        || Date.now() - lastCapabilityRead.current >= capabilityRefreshMilliseconds
      ) {
        const [capabilityResult, authorityResult] = await Promise.all([
          json<FactoryCapabilities>('capabilities'),
          json<FactoryAuthority>('authority'),
        ]);
        capabilityCache.current = capabilityResult;
        authorityCache.current = authorityResult;
        lastCapabilityRead.current = Date.now();
        setCapabilities(capabilityResult);
        setAuthority(authorityResult);
      }
      if (health.coordinator.state === 'ready') {
        const [snapshotResult, timingResult] = await Promise.all([
          json<CoordinatorSnapshot>('snapshot'),
          json<TimingSnapshot>('timings?limit=200')
            .then(value => ({ value, error: null }))
            .catch(caught => ({
              value: null,
              error: caught instanceof Error ? caught.message : 'Timing API unavailable',
            })),
        ]);
        setSnapshot(snapshotResult);
        setTimings(timingResult.value);
        setTimingsError(timingResult.error);
        await refreshEvents(snapshotResult);
      } else {
        setSnapshot(null);
        setTimings(null);
        setTimingsError(null);
        resetEvents();
      }
      hasSuccessfulRead.current = true;
      setConnection('live');
      setError(null);
      setLastUpdated(new Date());
    } catch (caught) {
      setConnection(hasSuccessfulRead.current ? 'stale' : 'offline');
      setError(caught instanceof Error ? caught.message : 'Coordinator API unavailable');
    } finally {
      refreshInFlight.current = false;
    }
  }, [refreshEvents, resetEvents]);

  useEffect(() => {
    const kickoff = window.setTimeout(() => void refresh(false), 0);
    const timer = window.setInterval(() => void refresh(false), pollMilliseconds);
    return () => {
      window.clearTimeout(kickoff);
      window.clearInterval(timer);
    };
  }, [pollMilliseconds, refresh]);

  const mutate = useCallback(
    async (action: 'sync' | 'pause' | 'resume', body: Record<string, unknown> = {}) => {
      setBusyAction(action);
      try {
        await json<Record<string, unknown>>(action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        await refresh(false);
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : 'Coordinator mutation failed');
      } finally {
        setBusyAction(null);
      }
    },
    [refresh],
  );

  const planDraft = useCallback(
    async (
      action: 'resolve' | 'save',
      body: Record<string, unknown>,
    ): Promise<PlanDraftResult> => {
      const busy = `plan-draft-${action}`;
      setBusyAction(busy);
      try {
        const result = await json<PlanDraftResult>(`plan-drafts/${action}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        setError(null);
        if (action === 'save') {
          authorityCache.current = null;
          await refresh(true);
        }
        return result;
      } catch (caught) {
        const message = caught instanceof Error ? caught.message : 'Plan draft failed';
        setError(message);
        throw caught;
      } finally {
        setBusyAction(null);
      }
    },
    [refresh],
  );

  return {
    connection,
    snapshot,
    capabilities,
    authority,
    events,
    timings,
    timingsError,
    eventHistoryLimited: Boolean(snapshot && snapshot.last_event_id > events.length),
    error,
    busyAction,
    lastUpdated,
    refresh: () => refresh(true),
    sync: () => mutate('sync'),
    pause: (reason: string) => mutate('pause', { reason }),
    resume: () => mutate('resume'),
    resolvePlanDraft: (toml: string) => planDraft('resolve', { toml }),
    savePlanDraft: (name: string, toml: string, expectedSha256?: string) => planDraft(
      'save',
      {
        name,
        toml,
        ...(expectedSha256 ? { expected_sha256: expectedSha256 } : {}),
      },
    ),
  };
}
