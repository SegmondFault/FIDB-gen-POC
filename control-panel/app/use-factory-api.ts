'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

import { settlePanelRead } from './panel-health.mjs';

import type {
  ConnectionState,
  CampaignRegistryStatus,
  CoordinatorEvent,
  CoordinatorSnapshot,
  EcologicalCase,
  EcologicalValidation,
  ExportStatus,
  FactoryAuthority,
  FactoryCapabilities,
  FidMatchingBackendStatus,
  HashAnalysisBackendStatus,
  LaneInventory,
  MachineValidation,
  MachineValidationLive,
  MachineValidationRun,
  NoisyHashRow,
  NoisyHashStatus,
  OperationsPreflight,
  PanelReadKey,
  PanelReadResult,
  PlanDraftResult,
  RetentionStatus,
  TimingSnapshot,
  ValidationObservatory,
} from './factory-api-types';

export type * from './factory-api-types';

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
const capabilityRefreshMilliseconds = 15 * 60_000;
const idlePollMilliseconds = 30_000;

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

async function panelJson<T>(key: PanelReadKey, path: string): Promise<PanelReadResult<T>> {
  return settlePanelRead(key, () => json<T>(path)) as Promise<PanelReadResult<T>>;
}

export function useFactoryApi(pollMilliseconds = 5000) {
  const [connection, setConnection] = useState<ConnectionState>('connecting');
  const [campaigns, setCampaigns] = useState<CampaignRegistryStatus | null>(null);
  const [snapshot, setSnapshot] = useState<CoordinatorSnapshot | null>(null);
  const [capabilities, setCapabilities] = useState<FactoryCapabilities | null>(null);
  const [authority, setAuthority] = useState<FactoryAuthority | null>(null);
  const [machineValidation, setMachineValidation] = useState<MachineValidation | null>(null);
  const [laneInventory, setLaneInventory] = useState<LaneInventory | null>(null);
  const [ecologicalValidation, setEcologicalValidation] = useState<EcologicalValidation | null>(null);
  const [noisyHashes, setNoisyHashes] = useState<NoisyHashStatus | null>(null);
  const [validationObservatory, setValidationObservatory] = useState<ValidationObservatory | null>(null);
  const [hashAnalysisBackend, setHashAnalysisBackend] = useState<HashAnalysisBackendStatus | null>(null);
  const [fidMatchingBackend, setFidMatchingBackend] = useState<FidMatchingBackendStatus | null>(null);
  const [retention, setRetention] = useState<RetentionStatus | null>(null);
  const [exportStatus, setExportStatus] = useState<ExportStatus | null>(null);
  const [events, setEvents] = useState<CoordinatorEvent[]>([]);
  const [timings, setTimings] = useState<TimingSnapshot | null>(null);
  const [preflight, setPreflight] = useState<OperationsPreflight | null>(null);
  const [timingsError, setTimingsError] = useState<string | null>(null);
  const [panelErrors, setPanelErrors] = useState<Partial<Record<PanelReadKey, string>>>({});
  const [error, setError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const hasSuccessfulRead = useRef(false);
  const refreshInFlight = useRef(false);
  const eventCursor = useRef(0);
  const eventHistory = useRef<CoordinatorEvent[]>([]);
  const selectedValidationRun = useRef<string | null>(null);
  const capabilityCache = useRef<FactoryCapabilities | null>(null);
  const authorityCache = useRef<FactoryAuthority | null>(null);
  const lastCapabilityRead = useRef(0);
  const recordPanelReads = useCallback((reads: Array<PanelReadResult<unknown>>) => {
    setPanelErrors(current => {
      const next = { ...current };
      for (const read of reads) {
        if (read.error) next[read.key] = read.error;
        else delete next[read.key];
      }
      return next;
    });
  }, []);
  const workloadActive = Boolean(
    machineValidation
    && ['queued', 'preparing-index', 'running', 'pausing', 'postprocessing', 'retaining'].includes(machineValidation.run.state),
  ) || Boolean(
    snapshot
    && (snapshot.counts.leased > 0 || snapshot.counts.running > 0),
  );
  const effectivePollMilliseconds = workloadActive
    ? pollMilliseconds
    : Math.max(pollMilliseconds, idlePollMilliseconds);

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
        const reads = await Promise.all([
          panelJson<FactoryCapabilities>('capabilities', 'capabilities'),
          panelJson<CampaignRegistryStatus>('campaigns', 'campaigns'),
          panelJson<FactoryAuthority>('authority', 'authority'),
          panelJson<LaneInventory>('lane-inventory', 'lane-inventory'),
          panelJson<EcologicalValidation>('ecological-validation', 'ecological-validation'),
          panelJson<RetentionStatus>('retention', 'retention'),
          panelJson<ValidationObservatory>('validation-observatory', `validation-observatory${selectedValidationRun.current ? `?run_id=${encodeURIComponent(selectedValidationRun.current)}` : ''}`),
          panelJson<HashAnalysisBackendStatus>('hash-analysis-backend', 'hash-analysis-backend'),
          panelJson<FidMatchingBackendStatus>('fid-matching-backend', 'fid-matching-backend'),
          panelJson<NoisyHashStatus>('noisy-hashes', 'noisy-hashes'),
          panelJson<ExportStatus>('export', 'export'),
        ]);
        recordPanelReads(reads as Array<PanelReadResult<unknown>>);
        const [capabilityRead, campaignRead, authorityRead, laneInventoryRead, ecologicalRead, retentionRead, observatoryRead, hashBackendRead, fidBackendRead, noisyRead, exportRead] = reads;
        if (capabilityRead.value) {
          capabilityCache.current = capabilityRead.value;
          setCapabilities(capabilityRead.value);
        }
        if (authorityRead.value) {
          authorityCache.current = authorityRead.value;
          setAuthority(authorityRead.value);
          setMachineValidation(authorityRead.value.machine_validations[0] ?? null);
        }
        if (campaignRead.value) setCampaigns(campaignRead.value);
        if (capabilityRead.value && authorityRead.value) lastCapabilityRead.current = Date.now();
        if (laneInventoryRead.value) setLaneInventory(laneInventoryRead.value);
        if (ecologicalRead.value) setEcologicalValidation(ecologicalRead.value);
        if (noisyRead.value) setNoisyHashes(noisyRead.value);
        if (retentionRead.value) setRetention(retentionRead.value);
        if (exportRead.value) setExportStatus(exportRead.value);
        if (observatoryRead.value) setValidationObservatory(observatoryRead.value);
        if (hashBackendRead.value) setHashAnalysisBackend(hashBackendRead.value);
        if (fidBackendRead.value) setFidMatchingBackend(fidBackendRead.value);
      } else {
        const reads = await Promise.all([
          panelJson<MachineValidationLive>('machine-validation/run', 'machine-validation/run'),
          panelJson<EcologicalValidation>('ecological-validation', 'ecological-validation'),
          panelJson<NoisyHashStatus>('noisy-hashes', 'noisy-hashes'),
          panelJson<RetentionStatus>('retention', 'retention'),
          panelJson<ValidationObservatory>('validation-observatory', `validation-observatory${selectedValidationRun.current ? `?run_id=${encodeURIComponent(selectedValidationRun.current)}` : ''}`),
          panelJson<HashAnalysisBackendStatus>('hash-analysis-backend', 'hash-analysis-backend'),
          panelJson<FidMatchingBackendStatus>('fid-matching-backend', 'fid-matching-backend'),
        ]);
        recordPanelReads(reads as Array<PanelReadResult<unknown>>);
        const [machineRead, ecologicalRead, noisyRead, retentionRead, observatoryRead, hashBackendRead, fidBackendRead] = reads;
        if (machineRead.value) {
          setMachineValidation(current => current ? {
            ...current,
            run: machineRead.value?.run ?? current.run,
            canary_gate: machineRead.value?.canary_gate ?? current.canary_gate,
            fid_matching: machineRead.value?.fid_matching ?? current.fid_matching,
          } : current);
        }
        if (ecologicalRead.value) setEcologicalValidation(ecologicalRead.value);
        if (noisyRead.value) setNoisyHashes(noisyRead.value);
        if (retentionRead.value) setRetention(retentionRead.value);
        if (observatoryRead.value) setValidationObservatory(observatoryRead.value);
        if (hashBackendRead.value) setHashAnalysisBackend(hashBackendRead.value);
        if (fidBackendRead.value) setFidMatchingBackend(fidBackendRead.value);
      }
      if (health.coordinator.state === 'ready') {
        const reads = await Promise.all([
          panelJson<CoordinatorSnapshot>('snapshot', 'snapshot?detail=control-panel'),
          panelJson<TimingSnapshot>('timings', 'timings?limit=200'),
          panelJson<OperationsPreflight>('preflight', 'preflight'),
        ]);
        recordPanelReads(reads as Array<PanelReadResult<unknown>>);
        const [snapshotRead, timingRead, preflightRead] = reads;
        if (snapshotRead.value) setSnapshot(snapshotRead.value);
        if (preflightRead.value) setPreflight(preflightRead.value);
        if (timingRead.value) setTimings(timingRead.value);
        setTimingsError(timingRead.error);
        if (snapshotRead.value) {
          const eventRead = await settlePanelRead(
            'events',
            async () => {
              await refreshEvents(snapshotRead.value as CoordinatorSnapshot);
              return true;
            },
          ) as PanelReadResult<boolean>;
          recordPanelReads([eventRead]);
        }
      } else {
        setSnapshot(null);
        setTimings(null);
        setPreflight(null);
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
  }, [recordPanelReads, refreshEvents, resetEvents]);

  useEffect(() => {
    const kickoff = window.setTimeout(() => void refresh(false), 0);
    const timer = window.setInterval(() => void refresh(false), effectivePollMilliseconds);
    return () => {
      window.clearTimeout(kickoff);
      window.clearInterval(timer);
    };
  }, [effectivePollMilliseconds, refresh]);

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

  const refreshValidation = useCallback(async () => {
    const [machineResult, ecologicalResult, noisyResult, observatoryResult] = await Promise.all([
      json<MachineValidation>('machine-validation'),
      json<EcologicalValidation>('ecological-validation'),
      json<NoisyHashStatus>('noisy-hashes'),
      json<ValidationObservatory>(`validation-observatory${selectedValidationRun.current ? `?run_id=${encodeURIComponent(selectedValidationRun.current)}` : ''}`),
    ]);
    setMachineValidation(machineResult);
    setEcologicalValidation(ecologicalResult);
    setNoisyHashes(noisyResult);
    setValidationObservatory(observatoryResult);
    setError(null);
  }, []);

  const selectValidationRun = useCallback(async (runKey: string) => {
    try {
      const result = await json<ValidationObservatory>(
        `validation-observatory?run_id=${encodeURIComponent(runKey)}`,
      );
      selectedValidationRun.current = runKey;
      setValidationObservatory(result);
      setError(null);
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Validation run unavailable';
      setError(message);
      throw caught;
    }
  }, []);

  const runMachineValidation = useCallback(async (mode: 'canary' | 'full', runId?: string) => {
    setBusyAction(`machine-validation-${mode}`);
    try {
      await json<MachineValidationRun>('machine-validation/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, ...(runId ? { run_id: runId } : {}) }),
      });
      await refreshValidation();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Machine validation failed to start';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, [refreshValidation]);

  const controlMachineValidation = useCallback(async (action: 'pause' | 'resume') => {
    setBusyAction(`machine-validation-${action}`);
    try {
      await json<MachineValidationRun>(`machine-validation/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      await refreshValidation();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : `Machine validation failed to ${action}`;
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, [refreshValidation]);

  const importEcological = useCallback(async (
    file: File,
    metadata: {
      label: string;
      platformHint: string;
      expectedPresent: string[];
      expectedAbsent: string[];
      truthComplete: boolean;
    },
  ) => {
    setBusyAction('ecological-import');
    try {
      const response = await fetch('/api/fidb/ecological-validation/import', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-FIDB-Filename': encodeURIComponent(file.name),
          'X-FIDB-Label': encodeURIComponent(metadata.label),
          'X-FIDB-Platform-Hint': metadata.platformHint,
          'X-FIDB-Expected-Present': encodeURIComponent(metadata.expectedPresent.join(',')),
          'X-FIDB-Expected-Absent': encodeURIComponent(metadata.expectedAbsent.join(',')),
          'X-FIDB-Truth-Complete': String(metadata.truthComplete),
        },
        body: file,
      });
      const document = await response.json() as ApiErrorBody;
      if (!response.ok) {
        throw new Error(document.error?.message ?? `Ecological import failed (${response.status})`);
      }
      await refreshValidation();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Ecological import failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, [refreshValidation]);

  const runEcological = useCallback(async (caseId: string) => {
    setBusyAction(`ecological-run:${caseId}`);
    try {
      await json<EcologicalCase>('ecological-validation/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId }),
      });
      await refreshValidation();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Ecological check failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, [refreshValidation]);

  const decideNoisyHash = useCallback(async (
    signatureId: string,
    state: NoisyHashRow['disposition'],
    reason: string,
  ) => {
    setBusyAction(`noisy-hash:${signatureId}`);
    try {
      const result = await json<NoisyHashStatus>('noisy-hashes/decision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ signature_id: signatureId, state, reason }),
      });
      setNoisyHashes(result);
      setError(null);
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Noisy-hash decision failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, []);

  const runRetention = useCallback(async (
    action: 'plan' | 'apply',
    planDigest?: string,
  ) => {
    setBusyAction(`retention-${action}`);
    try {
      const result = await json<RetentionStatus>(`retention/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(action === 'apply' ? { plan_digest: planDigest } : {}),
      });
      setRetention(result);
      setError(null);
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Retention action failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, []);

  const runExport = useCallback(async (action: 'preview' | 'safeguard' | 'build') => {
    setBusyAction(`export-${action}`);
    try {
      const result = await json<ExportStatus>(`export/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      setExportStatus(result);
      setError(null);
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : `Export ${action} failed`;
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, []);

  const setHashAnalysisMode = useCallback(async (mode: 'auto' | 'cpu' | 'gpu') => {
    setBusyAction('hash-analysis-mode');
    try {
      const result = await json<HashAnalysisBackendStatus>('hash-analysis-backend/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      });
      setHashAnalysisBackend(result);
      setError(null);
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Hash backend setting failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, []);

  const setFidMatchingMode = useCallback(async (mode: 'auto' | 'cpu' | 'gpu') => {
    setBusyAction('fid-matching-mode');
    try {
      const result = await json<FidMatchingBackendStatus>('fid-matching-backend/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      });
      setFidMatchingBackend(result);
      setError(null);
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'FID matching backend setting failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, []);

  const selectCampaign = useCallback(async (campaignId: string) => {
    setBusyAction('campaign-select');
    try {
      const result = await json<CampaignRegistryStatus>('campaigns/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ campaign_id: campaignId }),
      });
      setCampaigns(result);
      setSnapshot(null);
      setTimings(null);
      setPreflight(null);
      resetEvents();
      capabilityCache.current = null;
      await refresh(true);
      setError(null);
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Campaign selection failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, [refresh, resetEvents]);

  return {
    connection,
    campaigns,
    snapshot,
    capabilities,
    authority,
    machineValidation,
    laneInventory,
    ecologicalValidation,
    noisyHashes,
    validationObservatory,
    hashAnalysisBackend,
    fidMatchingBackend,
    retention,
    exportStatus,
    events,
    timings,
    preflight,
    timingsError,
    panelErrors,
    eventHistoryLimited: Boolean(snapshot && snapshot.last_event_id > events.length),
    error,
    busyAction,
    lastUpdated,
    refresh: () => refresh(true),
    sync: () => mutate('sync'),
    pause: (reason: string) => mutate('pause', { reason }),
    resume: () => mutate('resume'),
    selectCampaign,
    resolvePlanDraft: (toml: string) => planDraft('resolve', { toml }),
    savePlanDraft: (name: string, toml: string, expectedSha256?: string) => planDraft(
      'save',
      {
        name,
        toml,
        ...(expectedSha256 ? { expected_sha256: expectedSha256 } : {}),
      },
    ),
    importEcological,
    runEcological,
    runMachineValidation,
    selectValidationRun,
    setHashAnalysisMode,
    setFidMatchingMode,
    pauseMachineValidation: () => controlMachineValidation('pause'),
    resumeMachineValidation: () => controlMachineValidation('resume'),
    decideNoisyHash,
    planRetention: () => runRetention('plan'),
    applyRetention: (planDigest: string) => runRetention('apply', planDigest),
    previewExport: () => runExport('preview'),
    safeguardExport: () => runExport('safeguard'),
    buildExport: () => runExport('build'),
  };
}
