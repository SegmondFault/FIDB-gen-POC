'use client';

import { Fragment, useEffect, useState, useSyncExternalStore, type CSSProperties } from 'react';
import {
  useFactoryApi,
  type CoordinatorAttempt,
  type CoordinatorBatch,
  type CoordinatorEvent,
  type CoordinatorJob,
  type CoordinatorSnapshot,
  type StageSpan,
  type TimingEta,
  type PlanDraftResult,
} from './use-factory-api';

const navItems = [
  ['01', 'Overview'],
  ['02', 'Matrix'],
  ['03', 'Timing'],
  ['04', 'Batches'],
  ['05', 'Toolchains'],
  ['06', 'Evidence'],
];

type BatchRow = {
  id: string;
  name: string;
  status: 'Defined' | 'Running' | 'Blocked' | 'Complete' | 'Queued';
  progress: string;
  percent: number;
  worker: string;
  route: string;
  eta: string;
  tier?: string;
  note?: string;
};

const interfaceScales = [0.9, 1, 1.15, 1.3] as const;
type InterfaceScale = (typeof interfaceScales)[number];
const interfaceScaleStorageKey = 'fidb-interface-scale';
const interfaceScaleChangeEvent = 'fidb-interface-scale-change';

function readInterfaceScale(): InterfaceScale {
  const saved = Number(window.localStorage.getItem(interfaceScaleStorageKey));
  return interfaceScales.includes(saved as InterfaceScale) ? saved as InterfaceScale : 1;
}

function subscribeInterfaceScale(onChange: () => void) {
  window.addEventListener('storage', onChange);
  window.addEventListener(interfaceScaleChangeEvent, onChange);
  return () => {
    window.removeEventListener('storage', onChange);
    window.removeEventListener(interfaceScaleChangeEvent, onChange);
  };
}

function batchStatus(jobs: CoordinatorJob[], snapshot: CoordinatorSnapshot): BatchRow['status'] {
  if (jobs.length && jobs.every(job => job.state === 'complete')) return 'Complete';
  if (jobs.some(job => job.state === 'running' || job.state === 'leased')) return 'Running';
  if (jobs.some(job => job.state === 'blocked' || job.state === 'failed')) return 'Blocked';
  if (snapshot.armed && jobs.some(job => job.state === 'queued')) return 'Queued';
  return 'Defined';
}

function resolvedBatchRows(snapshot: CoordinatorSnapshot): BatchRow[] {
  return snapshot.batches.map((batch: CoordinatorBatch) => {
    const jobs = snapshot.jobs.filter(job => job.batch_id === batch.id);
    const complete = jobs.filter(job => job.state === 'complete').length;
    const workers = Array.from(new Set(jobs.map(job => job.leased_by).filter(Boolean)));
    return {
      id: batch.id,
      name: batch.name,
      status: batchStatus(jobs, snapshot),
      progress: `${complete} / ${jobs.length} ${jobs.length === 1 ? 'job' : 'jobs'}`,
      percent: jobs.length ? Math.round((complete / jobs.length) * 100) : 0,
      worker: workers.join(', ') || '—',
      route: 'Library local',
      eta: '—',
      tier: batch.id === 'batch-000' ? 'T0' : undefined,
      note: batch.plan_path,
    };
  });
}

function eventTone(event: CoordinatorEvent) {
  if (event.event_type.includes('complete') || event.event_type.includes('synced')) return 'success';
  if (event.event_type.includes('fail') || event.event_type.includes('blocked')) return 'warning';
  return 'info';
}

function eventDetail(event: CoordinatorEvent) {
  const payload = Object.entries(event.payload)
    .slice(0, 3)
    .map(([key, value]) => `${key}=${typeof value === 'string' ? value : JSON.stringify(value)}`)
    .join(' · ');
  return [event.batch_id, event.job_id?.slice(0, 12), payload].filter(Boolean).join(' · ') || event.actor;
}

function eventTime(event: CoordinatorEvent, milliseconds = false) {
  const date = new Date(event.occurred_at);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: milliseconds ? 3 : undefined,
    hour12: false,
  });
}

function formatDurationNs(value: number | null | undefined) {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return '—';
  const milliseconds = value / 1_000_000;
  if (milliseconds < 1) return `${Math.round(value / 1_000)} µs`;
  if (milliseconds < 1_000) return `${milliseconds < 10 ? milliseconds.toFixed(1) : Math.round(milliseconds)} ms`;
  const seconds = milliseconds / 1_000;
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} s`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${minutes < 10 ? minutes.toFixed(1) : Math.round(minutes)} min`;
  const hours = minutes / 60;
  return `${hours < 10 ? hours.toFixed(1) : Math.round(hours)} h`;
}

function elapsedNs(startedAt: string, now: number, endedAt?: string | null) {
  const start = Date.parse(startedAt);
  const end = endedAt ? Date.parse(endedAt) : now;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null;
  return (end - start) * 1_000_000;
}

function formatStartedAt(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function stageLabel(value: string) {
  return value.replaceAll('-', ' ').replace(/\b\w/g, letter => letter.toUpperCase());
}

function formatBytes(value: number | null) {
  if (value === null || !Number.isFinite(value) || value < 0) return '—';
  if (value < 1024) return `${Math.round(value)} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let amount = value / 1024;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount < 10 ? amount.toFixed(1) : Math.round(amount)} ${units[unit]}`;
}

function numericMetric(span: StageSpan, key: string) {
  const value = span.metrics?.[key];
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

function resourceEvidence(span: StageSpan) {
  const cpu = [
    'self_user_cpu_duration_ns',
    'self_system_cpu_duration_ns',
    'child_user_cpu_duration_ns',
    'child_system_cpu_duration_ns',
  ].map(key => numericMetric(span, key)).filter((value): value is number => value !== null)
    .reduce((sum, value) => sum + value, 0);
  const rssValues = [
    numericMetric(span, 'self_max_rss_bytes_peak'),
    numericMetric(span, 'child_max_rss_bytes_peak'),
  ].filter((value): value is number => value !== null);
  const rss = rssValues.length ? Math.max(...rssValues) : null;
  const programs = numericMetric(span, 'program_count') ?? numericMetric(span, 'programs');
  const details = [
    typeof span.metrics?.cache_hit === 'boolean' ? `cache ${span.metrics.cache_hit ? 'hit' : 'miss'}` : null,
    numericMetric(span, 'bytes') !== null ? `${formatBytes(numericMetric(span, 'bytes'))} I/O` : null,
    numericMetric(span, 'object_count') !== null ? `${numericMetric(span, 'object_count')} objects` : null,
    programs !== null ? `${programs} programs` : null,
    numericMetric(span, 'added') !== null ? `${numericMetric(span, 'added')} FID records added` : null,
  ].filter(Boolean);
  return {
    cpu,
    rss,
    details: details.join(' · '),
  };
}

function etaDuration(eta: TimingEta | null) {
  if (!eta) return null;
  for (const value of [
    eta.remaining_duration_ns,
    eta.p50_remaining_duration_ns,
  ]) {
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
  }
  return null;
}

export default function Home() {
  const [activeView, setActiveView] = useState('Matrix');
  const [batchOrder, setBatchOrder] = useState<string[]>([]);
  const interfaceScale = useSyncExternalStore<InterfaceScale>(subscribeInterfaceScale, readInterfaceScale, () => 1);
  const factory = useFactoryApi();
  const authorityBatchRows: BatchRow[] = (factory.authority?.plans ?? []).map(plan => {
    const desired = plan.summary.desired_cells ?? 0;
    const built = plan.inventory.summary.built ?? 0;
    const kinds = Array.from(new Set(plan.matrices.map(matrix => String(matrix.kind ?? 'unknown'))));
    const executors = Array.from(new Set(plan.matrices.map(matrix => (
      matrix.kind === 'native' ? 'native' : String(matrix.executor ?? 'unspecified')
    ))));
    return {
      id: `plan:${plan.name}`,
      name: plan.name,
      status: 'Defined',
      progress: `${built} / ${desired} ${desired === 1 ? 'cell' : 'cells'} sealed`,
      percent: desired ? Math.round((built / desired) * 100) : 0,
      worker: '—',
      route: `${kinds.join(' + ')} · ${executors.join(' + ')}`,
      eta: '—',
      tier: plan.policy.priority === 'high' ? 'T0' : undefined,
      note: plan.path,
    };
  });
  const currentBatchRows = factory.snapshot ? resolvedBatchRows(factory.snapshot) : authorityBatchRows;
  const effectiveBatchOrder = factory.snapshot
    ? factory.snapshot.batches.map(batch => batch.id)
    : batchOrder.length
      ? batchOrder
      : authorityBatchRows.map(batch => batch.id);

  const applyInterfaceScale = (scale: InterfaceScale) => {
    window.localStorage.setItem(interfaceScaleStorageKey, String(scale));
    window.dispatchEvent(new Event(interfaceScaleChangeEvent));
  };
  const scaleIndex = interfaceScales.indexOf(interfaceScale);
  const appScaleStyle = {
    '--ui-scale': interfaceScale,
  } as CSSProperties & {
    '--ui-scale': number;
  };
  const counts = factory.snapshot?.counts;
  const totalJobs = counts
    ? counts.blocked + counts.complete + counts.failed + counts.leased + counts.queued + counts.running
    : 0;
  const completeJobs = counts?.complete ?? 0;
  const completionPercent = totalJobs ? Math.round((completeJobs / totalJobs) * 100) : 0;
  const pool = factory.capabilities?.worker_pools['library-local'];
  const latestEvents = factory.events.slice(-4).reverse();
  const nextJob = factory.snapshot?.jobs.find(job => job.state === 'queued');
  const activeStageSpans = (factory.snapshot?.stage_attempts ?? factory.timings?.recent ?? [])
    .filter(span => span.state === 'started' && span.ended_at === null);
  const activeStageNames = new Set(activeStageSpans.map(span => span.stage));
  const measuredStages: Array<[string, string, number, string]> = (factory.timings?.stages ?? [])
    .map(stage => {
      const completed = stage.state_counts.completed ?? stage.sample_count;
      const skipped = stage.state_counts.skipped ?? 0;
      const resolved = completed + skipped;
      const terminal = resolved
        + (stage.state_counts.failed ?? 0)
        + (stage.state_counts.interrupted ?? 0);
      return [
        stageLabel(stage.stage),
        skipped ? `${resolved} resolved · ${skipped} skipped` : `${resolved} resolved`,
        terminal ? Math.round((resolved / terminal) * 100) : 0,
        activeStageNames.has(stage.stage) ? 'active' : resolved ? 'complete' : 'queued',
      ];
    });
  const measuredStageNames = new Set((factory.timings?.stages ?? []).map(stage => stage.stage));
  const activeOnlyStages: Array<[string, string, number, string]> = activeStageSpans
    .filter(span => !measuredStageNames.has(span.stage))
    .map(span => [stageLabel(span.stage), 'active', 45, 'active']);
  const overviewStages = [...activeOnlyStages, ...measuredStages].slice(0, 9);
  if (!overviewStages.length) overviewStages.push(['Collecting timing evidence', '0 samples', 0, 'queued']);
  const connectionLabel = factory.connection === 'live'
    ? `Live · ${factory.lastUpdated?.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) ?? 'now'}`
    : factory.connection === 'stale'
      ? 'Stale · retrying'
      : factory.connection === 'connecting'
        ? 'Connecting…'
        : 'Coordinator offline';

  return (
    <main className="app-shell" style={appScaleStyle}>
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div>
            <p className="brand-name">FIDB FACTORY</p>
            <p className="brand-subtitle">CONTROL PLANE</p>
          </div>
        </div>

        <div className="host-status">
          <span className={factory.connection === 'live' ? 'pulse-dot' : 'pulse-dot offline'} />
          <div>
            <strong>reference-host</strong>
            <span>{factory.connection === 'live' ? 'local API online' : 'control panel online'}</span>
          </div>
        </div>

        <nav className="primary-nav" aria-label="Main navigation">
          <p className="nav-label">Workspace</p>
          {navItems.map(([number, label]) => (
            <button
              className={activeView === label ? 'nav-item active' : 'nav-item'}
              key={label}
              onClick={() => setActiveView(label)}
            >
              <span>{number}</span>
              {label}
              {label === 'Batches' && <em>{currentBatchRows.filter(batch => batch.status !== 'Complete').length}</em>}
            </button>
          ))}
          <p className="nav-label secondary-label">Operations</p>
          <button className={activeView === 'Automation' ? 'nav-item active' : 'nav-item'} onClick={() => setActiveView('Automation')}>
            <span>07</span>
            Automation
          </button>
          <button className={activeView === 'Activity' ? 'nav-item active' : 'nav-item'} onClick={() => setActiveView('Activity')}>
            <span>08</span>
            Activity
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="environment-card">
            <span className="environment-key">ENV</span>
            <div>
              <strong>Production</strong>
              <span>post-unification</span>
            </div>
          </div>
          <button className="operator-button" aria-label="Operator menu">
            <span className="avatar">GA</span>
            <span>
              <strong>Local operator</strong>
              <small>full control</small>
            </span>
            <b>•••</b>
          </button>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <h1 className="page-headline">FIDB FACTORY <span>/</span> {activeView.toUpperCase()}</h1>
          <div className="topbar-actions">
            <div className="interface-scale-control" role="group" aria-label="Interface text size">
              <span>TEXT</span>
              <button
                onClick={() => applyInterfaceScale(interfaceScales[scaleIndex - 1])}
                disabled={scaleIndex === 0}
                aria-label="Decrease interface text size"
                title="Decrease text size"
              >A−</button>
              <button
                className="scale-value"
                onClick={() => applyInterfaceScale(1)}
                aria-label={`Reset interface text size. Current scale ${Math.round(interfaceScale * 100)} percent`}
                title="Reset text size"
              ><output aria-live="polite">{Math.round(interfaceScale * 100)}%</output></button>
              <button
                onClick={() => applyInterfaceScale(interfaceScales[scaleIndex + 1])}
                disabled={scaleIndex === interfaceScales.length - 1}
                aria-label="Increase interface text size"
                title="Increase text size"
              >A+</button>
            </div>
            <div className={`sync-state ${factory.connection}`} title={factory.error ?? undefined}>
              <span />
              {connectionLabel}
            </div>
            <button className="icon-button" aria-label="Notifications">
              <span className="notification-dot" />
              ⌁
            </button>
            <button className="command-button"><kbd>⌘</kbd> Command</button>
          </div>
        </header>

        <div className="content-scroll">
          {activeView === 'Overview' ? <>
          <section className="campaign-banner">
            <div className="campaign-main">
              <div className="campaign-kicker">
                <span className={`status-pill ${factory.snapshot?.armed ? 'active' : 'queued'}`}>QUEUE {factory.snapshot?.status.toUpperCase() ?? 'UNKNOWN'}</span>
                <span>plans/priority-queue.toml</span>
              </div>
              <h2>Local library production queue</h2>
              <p>{totalJobs} typed jobs across {currentBatchRows.length} batches · native and explicit local cross-builds · QEMU excluded</p>
            </div>
            <div className="campaign-progress">
              <div className="progress-ring" style={{ '--progress': `${completionPercent}%` } as CSSProperties}>
                <strong>{completionPercent}%</strong>
              </div>
              <div>
                <span>{completeJobs} of {totalJobs} jobs</span>
                <strong>{factory.snapshot?.status ?? 'Not connected'}</strong>
              </div>
            </div>
            <div className="campaign-actions">
              <button className="ghost-button" disabled>{factory.snapshot?.active_workers ? `${factory.snapshot.active_workers} active` : 'Nothing leased'}</button>
              <button className="pause-button" onClick={() => setActiveView('Automation')}>Review automation</button>
            </div>
          </section>

          <section className="metrics-grid" aria-label="Campaign metrics">
            <article className="metric-card">
              <div className="metric-top"><span>QUEUE</span><b className="metric-symbol">≋</b></div>
              <strong>{totalJobs}</strong>
              <p><i className="healthy">●</i> TOML-ordered · {factory.snapshot?.status ?? 'API unavailable'}</p>
            </article>
            <article className="metric-card">
              <div className="metric-top"><span>WORKER SLOTS</span><b className="metric-symbol">⌘</b></div>
              <strong>{factory.snapshot?.active_workers ?? '—'} <small>/ {factory.snapshot?.max_workers ?? '—'}</small></strong>
              <p><i className={factory.snapshot?.active_workers ? 'healthy' : 'warning'}>●</i> local library lease cap</p>
            </article>
            <article className="metric-card">
              <div className="metric-top"><span>SUCCESS RATE</span><b className="metric-symbol">⌁</b></div>
              <strong>{completeJobs ? `${Math.round((completeJobs / Math.max(1, completeJobs + (counts?.failed ?? 0))) * 100)}%` : '—'}</strong>
              <p><i className="warning">●</i> {completeJobs ? 'sealed ledger results' : 'no completed queue jobs'}</p>
            </article>
            <article className="metric-card warning-card">
              <div className="metric-top"><span>REQUIREMENTS</span><b className="metric-symbol">!</b></div>
              <strong>{pool ? pool.eligible_jobs - pool.ready_now : '—'}</strong>
              <p><i className="warning">●</i> active jobs need setup or acquisition</p>
            </article>
          </section>

          <section className="dashboard-grid">
            <article className="panel pipeline-panel">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">NEXT PRIORITY BATCH</p>
                  <h3>{currentBatchRows[0]?.name ?? 'No batch'} / {currentBatchRows[0]?.id ?? '—'}</h3>
                </div>
                <button className="text-button" onClick={() => setActiveView('Batches')}>View batch&nbsp; →</button>
              </div>
              <div className="pipeline-list">
                {overviewStages.map(([label, count, progress, state]) => (
                  <div className="pipeline-row" key={label}>
                    <span className={`stage-state ${state}`}>{state === 'complete' ? '✓' : state === 'active' ? '•' : ''}</span>
                    <strong>{label}</strong>
                    <div className="stage-track"><span style={{ width: `${progress}%` }} /></div>
                    <span className="stage-count">{count}</span>
                  </div>
                ))}
              </div>
              <div className="current-cell">
                <div className="cell-icon">P</div>
                <div>
                  <span>NEXT QUEUEABLE CELL</span>
                  <strong>{nextJob?.base_cell ?? 'No queued cell'}</strong>
                  <small>{nextJob ? `${nextJob.batch_id} · typed reviewed route · full Ghidra/FIDB pipeline` : 'Queue is drained or not synchronized'}</small>
                </div>
                <div className="cell-time">
                  <span>{activeStageSpans[0] ? stageLabel(activeStageSpans[0].stage) : '—'}</span>
                  <small>{activeStageSpans[0] ? `started ${formatStartedAt(activeStageSpans[0].started_at)}` : nextJob ? 'not leased' : 'no pending work'}</small>
                </div>
              </div>
            </article>

            <article className="panel workers-panel">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">EXECUTION</p>
                  <h3>Worker pool</h3>
                </div>
                <button className="round-add" aria-label="Worker enrollment is configured on the coordinator" disabled>+</button>
              </div>
              <div className="worker-list">
                {factory.capabilities ? [{
                  name: 'reference-host / library-local',
                  detail: `${factory.capabilities.host.logical_cpus ?? '—'} threads · ${Math.round((factory.capabilities.host.memory_bytes ?? 0) / 1024 ** 3)} GiB visible · no QEMU`,
                  state: factory.capabilities.analysis.ready ? `${pool?.ready_now ?? 0} ready now` : 'Analysis setup required',
                  tone: factory.capabilities.analysis.ready ? 'ready' : 'offline',
                }].map((worker) => (
                  <div className="worker-row" key={worker.name}>
                    <span className={`worker-glyph ${worker.tone}`}>⌬</span>
                    <div>
                      <strong>{worker.name}</strong>
                      <small>{worker.detail}</small>
                    </div>
                    <span className={`worker-state ${worker.tone}`}>{worker.state}</span>
                  </div>
                )) : <div className="empty-state"><span>◇</span><strong>No capability scan</strong><p>Connect the local API to inspect this host.</p></div>}
                {(factory.snapshot?.workers ?? []).map(worker => <div className="worker-row" key={worker.worker_id}><span className="worker-glyph ready">⌬</span><div><strong>{worker.worker_id}</strong><small>{worker.transport} · {worker.pools.join(', ')} · last seen {new Date(worker.last_seen_at).toLocaleString()}</small></div><span className="worker-state ready">{worker.state}</span></div>)}
              </div>
              <button className="full-width-button" onClick={() => setActiveView('Toolchains')}>Manage workers</button>
            </article>

            <article className="panel requirement-panel">
              <div className="alert-icon">!</div>
              <div className="alert-copy">
                <p className="panel-kicker">ACTION REQUIRED</p>
                <h3>{factory.connection === 'live' ? (factory.capabilities?.analysis.ready ? 'Library pool is visible' : 'Worker environment needs configuration') : 'Coordinator API unavailable'}</h3>
                <p>{factory.connection === 'live' ? `${pool?.ready_now ?? 0} jobs are ready immediately; ${pool?.runnable_with_pinned_acquisition ?? 0} can run after pinned acquisition. ${factory.capabilities?.analysis.ghidra.state === 'installed-unconfigured' ? 'Ghidra is installed but GHIDRA_HEADLESS is not configured for the API/worker service.' : ''}` : (factory.error ?? 'Start the loopback API service to read the durable ledger and toolchain inventory.')}</p>
                <div className="alert-tags"><span>library-local</span><span>max {factory.snapshot?.max_workers ?? 2}</span><span>no QEMU</span></div>
              </div>
              <button className="amber-button" onClick={() => setActiveView('Automation')}>Review automation</button>
            </article>

            <article className="panel activity-panel">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">LEDGER ACTIVITY</p>
                  <h3>{factory.connection === 'live' ? 'Latest durable events' : 'Waiting for coordinator'}</h3>
                </div>
                <button className="text-button" onClick={() => setActiveView('Activity')}>Open logs&nbsp; →</button>
              </div>
              <div className="event-list">
                {latestEvents.map(event => <div className="event-row" key={event.event_id}><time>{eventTime(event)}</time><span className={`event-dot ${eventTone(event)}`}/><p><strong>{event.event_type}</strong> {eventDetail(event)}</p></div>)}
                {!latestEvents.length && <div className="empty-state compact"><span>◇</span><strong>No live ledger events</strong><p>Synchronizing the queue will create the first durable event.</p></div>}
              </div>
            </article>
          </section>
          </> : <SecondaryView view={activeView} navigateTo={setActiveView} batchOrder={effectiveBatchOrder} setBatchOrder={setBatchOrder} rows={currentBatchRows} factory={factory} />}
        </div>
      </section>
    </main>
  );
}

type FactoryApiState = ReturnType<typeof useFactoryApi>;

function SecondaryView({ view, navigateTo, batchOrder, setBatchOrder, rows, factory }: { view: string; navigateTo: (view: string) => void; batchOrder: string[]; setBatchOrder: React.Dispatch<React.SetStateAction<string[]>>; rows: BatchRow[]; factory: FactoryApiState }) {
  if (view === 'Matrix') return <PlannerView batchOrder={batchOrder} rows={rows} factory={factory} />;
  if (view === 'Timing') return <TimingView factory={factory} />;
  if (view === 'Batches') return <BatchesView onNewBatch={() => navigateTo('Matrix')} batchOrder={batchOrder} setBatchOrder={setBatchOrder} rows={rows} live={Boolean(factory.snapshot)} />;
  if (view === 'Toolchains') return <ToolchainsView factory={factory} />;
  if (view === 'Evidence') return <EvidenceView snapshot={factory.snapshot} />;
  if (view === 'Automation') return <AutomationView factory={factory} />;
  return <ActivityView events={factory.events} connection={factory.connection} />;
}

function ViewIntro({ kicker, title, copy, action }: { kicker: string; title: string; copy: string; action?: React.ReactNode }) {
  return (
    <section className="view-intro">
      <div>
        <p className="panel-kicker">{kicker}</p>
        <h2>{title}</h2>
        <p>{copy}</p>
      </div>
      {action}
    </section>
  );
}

type RecipeMode = 'native' | 'source' | 'malware' | 'catalog';
type RecipeReadiness = 'source' | 'archive' | 'unmet' | 'artifact';
type RecipeOption = {
  id: string;
  name: string;
  version: string;
  mode: RecipeMode;
  matchSet: string;
  familyGroup: string;
  detail: string;
  coverage: string;
  readiness: RecipeReadiness;
  batch: string;
  planEligible: boolean;
  authority: string;
  recipePath?: string;
  adapter?: string;
  url?: string;
  sha256?: string;
  gap?: string;
  toolchainFamily?: string;
  toolchainVariants?: string[];
};

function PlannerView({ batchOrder, rows, factory }: { batchOrder: string[]; rows: BatchRow[]; factory: FactoryApiState }) {
  const executor = 'local';
  const timing = factory.timings;
  const [selectedRecipesOverride, setSelectedRecipesOverride] = useState<string[] | null>(null);
  const [routeSelectionsOverride, setRouteSelectionsOverride] = useState<Record<string, string[]> | null>(null);
  const [factorSelectionsOverride, setFactorSelectionsOverride] = useState<Record<string, string[]> | null>(null);
  const [collapsedVariableGroups, setCollapsedVariableGroups] = useState(['analysis-controls', 'environment-identity', 'fid-matching', 'truth-admission', 'hardening-instrumentation', 'link-output', 'analysis-recovery']);
  const [collapsedLibraryGroups, setCollapsedLibraryGroups] = useState<string[]>([]);
  const [matrixLayer, setMatrixLayer] = useState<'both' | 'plan' | 'inventory'>('both');
  const [queueStrategyOverride, setQueueStrategyOverride] = useState<string | null>(null);
  const [queueMessage, setQueueMessage] = useState('');
  const [inspectedRecipe, setInspectedRecipe] = useState<string | null>(null);
  const [inspectedFactor, setInspectedFactor] = useState<string | null>(null);
  const [tomlOpen, setTomlOpen] = useState(true);
  const [draftName, setDraftName] = useState('matrix-draft');
  const [draftResult, setDraftResult] = useState<PlanDraftResult | null>(null);
  const [validatedToml, setValidatedToml] = useState<string | null>(null);
  const [savedDraftSha256, setSavedDraftSha256] = useState<string | null>(null);
  const [draftMessage, setDraftMessage] = useState('Resolve the generated request before saving it.');
  const authority = factory.authority;
  const inventoryCells = authority?.plans.flatMap(plan => (
    Object.entries(plan.inventory.cells)
  )) ?? [];
  const builtCellIds = new Set(
    inventoryCells
      .filter(([, inventory]) => inventory.state === 'built')
      .map(([cellId]) => cellId),
  );
  const artifactOnlyCellIds = new Set(
    inventoryCells
      .filter(([, inventory]) => inventory.state === 'artifact-only')
      .map(([cellId]) => cellId),
  );
  const cellMatchesRecipe = (cellId: string, name: string, version: string) => (
    cellId.includes(':' + name + '-' + version + ':')
    || cellId.includes(':' + name + '@' + version + ':')
  );
  const authorityPlanForBatch = (batchId: string) => {
    const livePath = factory.snapshot?.batches.find(batch => batch.id === batchId)?.plan_path;
    const configuredName = rows.find(row => row.id === batchId)?.name;
    return authority?.plans.find(plan => (
      (livePath && plan.path === livePath)
      || (!livePath && configuredName && plan.name === configuredName)
    ));
  };
  const batchForRecipe = (recipeId: string) => {
    for (const batchId of batchOrder) {
      const plan = authorityPlanForBatch(batchId);
      const selected = plan?.matrices.some(matrix => (
        Array.isArray(matrix.recipes) && matrix.recipes.includes(recipeId)
      ));
      if (selected) return batchId;
    }
    return 'unassigned';
  };
  const recipeOptions: RecipeOption[] = (authority?.recipes ?? []).map(recipe => {
    const mode: RecipeMode = recipe.kind === 'native'
      ? 'native'
      : recipe.kind === 'malware'
        ? 'malware'
        : 'source';
    const matchingToolchains = (authority?.toolchains ?? []).filter(toolchain => (
      toolchain.family === recipe.toolchain_family
      && (!recipe.toolchain_variants?.length
        || recipe.toolchain_variants.includes(toolchain.variant))
    ));
    const sealedCount = [...builtCellIds].filter(cellId => (
      cellMatchesRecipe(cellId, recipe.name, recipe.version)
    )).length;
    const artifactOnlyCount = [...artifactOnlyCellIds].filter(cellId => (
      cellMatchesRecipe(cellId, recipe.name, recipe.version)
    )).length;
    const sourceReady = mode === 'native'
      || matchingToolchains.some(toolchain => toolchain.source_capable);
    const archiveCount = matchingToolchains.filter(toolchain => (
      toolchain.archive_capable
    )).length;
    const readiness: RecipeReadiness = sealedCount > 0
      ? 'artifact'
      : sourceReady
        ? 'source'
        : archiveCount > 0
          ? 'archive'
          : 'unmet';
    const coverage = sealedCount > 0
      ? sealedCount + ' sealed build' + (sealedCount === 1 ? '' : 's')
      : artifactOnlyCount > 0
        ? artifactOnlyCount + ' unsealed artifact' + (artifactOnlyCount === 1 ? '' : 's')
        : archiveCount > 0 && !sourceReady
          ? archiveCount + ' archive pin' + (archiveCount === 1 ? '' : 's')
          : 'not built';
    const familyGroup = recipe.kind === 'native'
      ? 'Native support libraries'
      : recipe.kind === 'malware'
        ? 'Ground-truth workloads'
        : (recipe.toolchain_family ?? 'Cross-built libraries') + ' runtime family';
    return {
      id: recipe.name,
      name: recipe.name,
      version: recipe.version,
      mode,
      matchSet: recipe.kind === 'malware'
        ? 'Ground-truth match set'
        : 'Reviewed reference match set',
      familyGroup,
      detail: recipe.build_adapter + ' · ' + (recipe.static_archives?.join(', ') ?? recipe.library_path ?? 'reviewed output'),
      coverage,
      readiness,
      batch: batchForRecipe(recipe.id),
      planEligible: recipe.kind !== 'malware' && sourceReady,
      authority: recipe.authority_path,
      recipePath: recipe.authority_path,
      adapter: recipe.build_adapter,
      url: recipe.url,
      sha256: recipe.sha256,
      gap: sourceReady
        ? undefined
        : 'No reviewed executable source route is registered for this recipe.',
      toolchainFamily: recipe.toolchain_family,
      toolchainVariants: recipe.toolchain_variants,
    };
  });
  const toolchainOptions = (authority?.toolchains ?? []).map(toolchain => ({
    id: toolchain.id,
    title: toolchain.machine + ' · ' + toolchain.variant,
    compiler: toolchain.source_capable
      ? 'Pinned cross compiler · ' + toolchain.version
      : 'Pinned archive extraction · ' + toolchain.version,
    abi: String(toolchain.elf_class) + '-bit · ' + toolchain.endianness,
    language: toolchain.machine + ':' + toolchain.endianness + ':' + String(toolchain.elf_class),
    state: toolchain.source_capable ? 'source' : 'archive',
    ref: toolchain.id,
    variant: toolchain.variant,
    family: toolchain.family,
    sourceCapable: toolchain.source_capable,
    archiveCapable: toolchain.archive_capable,
  }));
  const factorById = new Map(
    (authority?.factors ?? []).map(factor => [factor.id, factor]),
  );
  const humanize = (value: string) => value
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
  const variantGroupIds = Array.from(new Set(
    (authority?.factor_variants ?? []).map(variant => variant.group),
  ));
  const factorGroups = variantGroupIds.map(groupId => ({
    id: groupId,
    label: humanize(groupId),
    note: 'named variants from sensitivity/variants.toml',
    options: (authority?.factor_variants ?? [])
      .filter(variant => variant.group === groupId)
      .map(variant => ({
        id: variant.id,
        factor: variant.factor,
        label: variant.label,
        detail: factorById.get(variant.factor)?.control ?? variant.authority,
        state: variant.state,
      })),
  }));
  const factorStageIds = Array.from(new Set(
    (authority?.factors ?? []).map(factor => factor.stage),
  ));
  const catalogFactorGroups = factorStageIds.map(stage => ({
    id: 'known-' + stage,
    label: humanize(stage),
    note: 'known sensitivity and provenance dimensions',
    options: (authority?.factors ?? [])
      .filter(factor => factor.stage === stage)
      .map(factor => ({
        id: factor.id,
        label: factor.label,
        detail: factor.impact,
        state: factor.confidence === 'observed-sensitive' ? 'recorded' : 'known',
      })),
  }));
  const allFactorOptions = factorGroups.flatMap(group => group.options);
  const knownFactorCount = authority?.factors.length ?? 0;
  const measuredFactorCount = authority?.factors.filter(factor => (
    factor.confidence.startsWith('observed')
  )).length ?? 0;
  const nativeRouteOptions = (authority?.native.routes ?? []).map(route => {
    const compiler = Array.isArray(route.compiler)
      ? route.compiler.join(' ')
      : String(route.compiler ?? 'reviewed compiler');
    const targetOs = String(route.target_os ?? 'unknown');
    const architecture = String(route.architecture ?? 'unknown');
    const binaryFormat = String(route.binary_format ?? 'unknown');
    return {
      id: route.id,
      label: `${targetOs} · ${architecture}`,
      detail: `${compiler} · ${binaryFormat}`,
      state: 'registered',
      compatible: ['native'],
      kind: 'route',
      target: `${targetOs} ${architecture} ${binaryFormat}`,
      compiler,
      analysis: `${String(route.ghidra_language ?? 'route mapped')} / ${String(route.ghidra_compiler_spec ?? 'default')}`,
    };
  });
  const routeColumns = [
    ...nativeRouteOptions,
    ...toolchainOptions.map(toolchain => ({
      ...toolchain,
      label: toolchain.title,
      detail: `${toolchain.compiler} · ${toolchain.abi}`,
      compatible: ['source', 'malware'],
      kind: 'route',
      target: toolchain.abi,
      analysis: toolchain.language,
    })),
  ];
  const matrixVariableGroups = [
    { id: 'platform-abi', label: 'Platform / ABI', note: 'route and target', options: routeColumns },
    ...catalogFactorGroups.map(group => ({ ...group, options: group.options.map(option => ({ ...option, kind: 'catalog', compatible: ['native', 'source', 'malware'] })) })),
    ...factorGroups.map(group => ({ ...group, options: group.options.map(option => ({ ...option, kind: 'factor', compatible: ['native'] })) })),
  ];
  const authorityDefaults = (() => {
    const recipes = new Set<string>();
    const routes: Record<string, string[]> = {};
    const factors: Record<string, string[]> = {};
    let strategy: string | undefined;
    if (!authority) return { recipes: [] as string[], routes, factors, strategy };
    for (const batchId of batchOrder) {
      const plan = authorityPlanForBatch(batchId);
      if (!plan) continue;
      strategy ||= plan.queue.strategy;
      const liveBatch = factory.snapshot?.batches.find(batch => batch.id === batchId);
      const matrices = liveBatch?.matrices
        ? plan.matrices.filter(matrix => liveBatch.matrices?.includes(String(matrix.id)))
        : plan.matrices;
      for (const matrix of matrices) {
        const recipeRefs = Array.isArray(matrix.recipes)
          ? matrix.recipes.filter((value): value is string => typeof value === 'string')
          : [];
        const matrixRoutes = matrix.kind === 'native'
          ? (Array.isArray(matrix.routes) ? matrix.routes : [])
          : (Array.isArray(matrix.toolchains) ? matrix.toolchains : []);
        const matrixFactors = Array.isArray(matrix.factor_variants)
          ? matrix.factor_variants
          : plan.coverage.factor_variants;
        for (const recipeRef of recipeRefs) {
          const recipeName = recipeRef.split('@', 1)[0];
          recipes.add(recipeName);
          routes[recipeName] = Array.from(new Set([
            ...(routes[recipeName] ?? []),
            ...matrixRoutes.filter((value): value is string => typeof value === 'string'),
          ]));
          factors[recipeName] = Array.from(new Set([
            ...(factors[recipeName] ?? []),
            ...matrixFactors.filter((value): value is string => typeof value === 'string'),
          ]));
        }
      }
    }
    return { recipes: [...recipes], routes, factors, strategy };
  })();
  const selectedRecipes = selectedRecipesOverride ?? authorityDefaults.recipes;
  const routeSelections = routeSelectionsOverride ?? authorityDefaults.routes;
  const factorSelections = factorSelectionsOverride ?? authorityDefaults.factors;
  const queueStrategy = queueStrategyOverride ?? authorityDefaults.strategy ?? 'recipe-then-variant';
  const batchRank = (batchId: string) => {
    const rank = batchOrder.indexOf(batchId);
    return rank < 0 ? Number.MAX_SAFE_INTEGER : rank;
  };
  const orderedRecipeOptions = [...recipeOptions].sort((left, right) => batchRank(left.batch) - batchRank(right.batch));
  const selectedRecipeRows = orderedRecipeOptions.filter(recipe => recipe.planEligible && selectedRecipes.includes(recipe.id));
  const inspected = recipeOptions.find(recipe => recipe.id === inspectedRecipe);
  const inspectedCatalogFactor = catalogFactorGroups.flatMap(group => group.options).find(option => option.id === inspectedFactor);
  const inspectedFactorGroup = catalogFactorGroups.find(group => group.options.some(option => option.id === inspectedFactor));
  const libraryGroups = batchOrder.map(batchId => {
    const batch = rows.find(row => row.id === batchId);
    return {
      id: batchId,
      label: batch?.name || batchId,
      note: `${batch?.status || 'Unknown'} · ${batch?.progress || 'no progress'}`,
      rows: orderedRecipeOptions.filter(recipe => recipe.batch === batchId),
    };
  }).concat(orderedRecipeOptions.some(recipe => recipe.batch === 'unassigned') ? [{
    id: 'unassigned',
    label: 'Unassigned reviewed subjects',
    note: 'Catalogued authority · not present in the active priority queue',
    rows: orderedRecipeOptions.filter(recipe => recipe.batch === 'unassigned'),
  }] : []);
  const combinationsForRecipe = (recipeId: string) => {
    const selectedRows = allFactorOptions.filter(option => (factorSelections[recipeId] || []).includes(option.id));
    const dimensions = selectedRows.reduce<Record<string, typeof selectedRows>>((groups, option) => {
      (groups[option.factor] ||= []).push(option);
      return groups;
    }, {});
    return Object.values(dimensions).reduce<Array<Array<(typeof selectedRows)[number]>>>((combinations, options) => combinations.flatMap(combination => options.map(option => [...combination, option])), [[]]);
  };
  const inventoryForRoute = (recipe: RecipeOption, routeId: string) => {
    const toolchain = toolchainOptions.find(row => row.id === routeId);
    const routeToken = toolchain ? `:${toolchain.variant}` : `:${routeId}:`;
    const matches = inventoryCells.filter(([cellId]) => (
      cellMatchesRecipe(cellId, recipe.name, recipe.version)
      && cellId.includes(routeToken)
    ));
    if (matches.some(([, inventory]) => inventory.state === 'built')) return 'built';
    if (matches.some(([, inventory]) => inventory.state === 'artifact-only')) return 'artifact-only';
    return 'not-built';
  };
  const routeIsCompatible = (recipe: RecipeOption, routeId: string) => {
    if (recipe.mode === 'native') {
      return nativeRouteOptions.some(route => route.id === routeId);
    }
    const toolchain = toolchainOptions.find(row => row.id === routeId);
    return Boolean(
      toolchain
      && toolchain.sourceCapable
      && toolchain.family === recipe.toolchainFamily
      && (!recipe.toolchainVariants?.length || recipe.toolchainVariants.includes(toolchain.variant)),
    );
  };
  const cells = selectedRecipeRows.flatMap(recipe => (routeSelections[recipe.id] || []).flatMap(routeId => {
    const nativeRoute = nativeRouteOptions.find(row => row.id === routeId);
    if (nativeRoute && recipe.mode === 'native') return [{
      id: `${recipe.id}:${routeId}`,
      recipeId: recipe.id,
      recipe: `${recipe.name} ${recipe.version}`,
      batch: recipe.batch,
      target: nativeRoute.target,
      toolchain: nativeRoute.compiler,
      treatment: 'baseline_o2',
      analysis: nativeRoute.analysis,
      status: 'planned',
      route: 'native-local',
      coverage: inventoryForRoute(recipe, routeId),
    }];
    const toolchain = toolchainOptions.find(row => row.id === routeId);
    if (!toolchain || recipe.mode === 'native') return [];
    return [{
      id: `${recipe.id}-${toolchain.id}`, recipeId: recipe.id, recipe: `${recipe.name} ${recipe.version}`, batch: recipe.batch, target: toolchain.abi,
      toolchain: toolchain.compiler, treatment: recipe.mode === 'malware' ? (recipe.adapter ?? 'reviewed adapter') : 'adapter-owned',
      analysis: toolchain.language, status: routeIsCompatible(recipe, routeId) ? 'planned' : 'blocked', route: executor,
      coverage: inventoryForRoute(recipe, routeId),
    }];
  }));
  const unorderedQueuePairs = cells.flatMap(cell => combinationsForRecipe(cell.recipeId).map(combination => ({ cell, combination })));
  const queuePairs = queueStrategy === 'recipe-then-variant' ? unorderedQueuePairs : [...unorderedQueuePairs].sort((left, right) => left.combination.map(option => option.id).join('|').localeCompare(right.combination.map(option => option.id).join('|')) || cells.indexOf(left.cell) - cells.indexOf(right.cell));
  const executionQueue = queuePairs.map((item, index) => {
    const unsupported = item.combination.some(option => option.state !== 'registered');
    return { ...item, position: index + 1, state: item.cell.status === 'blocked' || unsupported ? 'blocked' : 'queueable' };
  });
  const desiredCellCount = executionQueue.length;
  const plannedCells = executionQueue.filter(row => row.state === 'queueable').length;
  const blockedCells = Math.max(0, desiredCellCount - plannedCells);
  const builtExecutions = executionQueue.filter(row => row.cell.coverage === 'built').length;
  const tierZeroBatchIds = new Set(rows.filter(batch => batch.tier === 'T0').map(batch => batch.id));
  const tierZeroSubjects = recipeOptions.filter(recipe => tierZeroBatchIds.has(recipe.batch));
  const tierZeroGapCount = tierZeroSubjects.filter(recipe => !recipe.planEligible).length;
  const malwareRecipe = recipeOptions.find(recipe => recipe.mode === 'malware');
  const malwareInventory = malwareRecipe ? inventoryCells.filter(([cellId]) => (
    cellMatchesRecipe(cellId, malwareRecipe.name, malwareRecipe.version)
  )) : [];
  const measuredEtaNs = etaDuration(timing?.eta ?? null);
  const selectedFactorRows = allFactorOptions.filter(option => selectedRecipeRows.some(recipe => (factorSelections[recipe.id] || []).includes(option.id)));
  const toggleRecipe = (id: string) => {
    if (!recipeOptions.find(recipe => recipe.id === id)?.planEligible) return;
    setSelectedRecipesOverride(current => {
      const selected = current ?? selectedRecipes;
      return selected.includes(id) ? selected.filter(item => item !== id) : [...selected, id];
    });
  };
  const toggleRoute = (recipeId: string, routeId: string) => setRouteSelectionsOverride(current => {
    const selections = current ?? routeSelections;
    const selected = selections[recipeId] ?? [];
    return { ...selections, [recipeId]: selected.includes(routeId) ? selected.filter(item => item !== routeId) : [...selected, routeId] };
  });
  const toggleFactor = (recipeId: string, factorId: string) => setFactorSelectionsOverride(current => {
    const selections = current ?? factorSelections;
    const selected = selections[recipeId] ?? [];
    return { ...selections, [recipeId]: selected.includes(factorId) ? selected.filter(item => item !== factorId) : [...selected, factorId] };
  });
  const toggleVariableGroup = (id: string) => setCollapsedVariableGroups(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id]);
  const toggleLibraryGroup = (id: string) => setCollapsedLibraryGroups(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id]);
  const plannedRecipeRows = selectedRecipeRows.filter(recipe => (routeSelections[recipe.id] || []).length > 0);
  const displayedVariableGroups = matrixVariableGroups.map(group => ({
    ...group,
    collapsed: collapsedVariableGroups.includes(group.id),
    displayedOptions: collapsedVariableGroups.includes(group.id) ? [{ id: `${group.id}:summary`, label: `${group.options.length} variables`, detail: group.note, state: 'summary', compatible: ['native', 'source', 'malware'], kind: 'summary' }] : group.options,
  }));
  const matrixColumnCount = displayedVariableGroups.reduce((total, group) => total + group.displayedOptions.length, 0);
  const toml = [
    'schema_version = "fidb-plan/v1"',
    `name = "${draftName}"`,
    '',
    '[policy]',
    'max_cells = 256',
    'priority = "normal"',
    '',
    '[coverage]',
    'factor_variants = []',
    '',
    '[queue]',
    `strategy = "${queueStrategy}"`,
    'recipe_order = [',
    ...plannedRecipeRows.map(recipe => `  "${recipe.id}@${recipe.version}",`),
    ']',
    ...plannedRecipeRows.flatMap(recipe => {
      const factorLines = (factorSelections[recipe.id] || []).map(id => `  "${id}",`);
      if (recipe.mode === 'native') {
        const nativeRoutes = (routeSelections[recipe.id] || []).filter(id => (
          nativeRouteOptions.some(route => route.id === id)
        ));
        return ['', '[[matrix]]', `id = "${recipe.id}-native"`, 'kind = "native"', `recipes = ["${recipe.id}@${recipe.version}"]`, `routes = [${nativeRoutes.map(id => `"${id}"`).join(', ')}]`, 'treatments = ["baseline_o2"]', 'factor_variants = [', ...factorLines, ']'];
      }
      const toolchainLines = (routeSelections[recipe.id] || []).map(id => toolchainOptions.find(toolchain => toolchain.id === id)).filter((row): row is (typeof toolchainOptions)[number] => Boolean(row)).map(row => `  "${row.ref}",`);
      return ['', '[[matrix]]', `id = "${recipe.id}-cross"`, `kind = "${recipe.mode === 'malware' ? 'malware' : 'source-library'}"`, `recipes = ["${recipe.id}@${recipe.version}"]`, 'toolchains = [', ...toolchainLines, ']', `executor = "${executor}"`, 'factor_variants = [', ...factorLines, ']'];
    }),
  ].join('\n');
  const savedAuthorityDraft = authority?.plans.find(plan => (
    plan.path === `plans/drafts/${draftName}.toml`
  ));
  const draftIsCurrent = validatedToml === toml && draftResult !== null;
  const resolveDraft = async () => {
    try {
      const result = await factory.resolvePlanDraft(toml);
      setDraftResult(result);
      setValidatedToml(toml);
      setDraftMessage(`Resolved ${result.resolved.summary.desired_cells ?? 0} desired executions; digest ${result.resolved.plan_digest.slice(0, 12)}…`);
    } catch (error) {
      setDraftResult(null);
      setValidatedToml(null);
      setDraftMessage(error instanceof Error ? error.message : 'Draft resolution failed.');
    }
  };
  const saveDraft = async () => {
    if (!draftIsCurrent) return;
    try {
      const result = await factory.savePlanDraft(
        draftName,
        toml,
        savedDraftSha256 ?? savedAuthorityDraft?.toml_sha256,
      );
      setDraftResult(result);
      setValidatedToml(toml);
      setSavedDraftSha256(result.toml_sha256);
      setDraftMessage(`Saved ${result.path}; plan digest ${result.resolved.plan_digest.slice(0, 12)}…`);
    } catch (error) {
      setDraftMessage(error instanceof Error ? error.message : 'Draft save failed.');
    }
  };
  return (
    <div className="view-stack">
      <ViewIntro kicker="ANALYST MATRIX" title="The whole factory in one view" copy="Libraries and match sets run down the batch-ordered left edge; every known platform, compiler, build and analysis variable runs across the top. Use the intersections to inspect coverage, plan precise work, and see queued, built, unbuilt and blocked state." action={<button className="secondary-action" onClick={() => setTomlOpen(!tomlOpen)}>{tomlOpen ? 'Hide' : 'Show'} TOML</button>} />

      <section className="plan-source-bar">
        <div><span className="source-glyph">T</span><p><strong>plans/priority-queue.toml</strong><small>fidb-queue/v1 · batch order points to immutable fidb-plan/v1 requests</small></p></div>
        <span className="authority-badge">PRIORITY AUTHORITY</span>
      </section>

      <div className="matrix-workspace">
        <section className="panel crosspoint-matrix-panel">
          <div className="matrix-main-header"><div><p className="panel-kicker">MAIN BUILD MATRIX</p><h2>Libraries × platforms × FID variables</h2><small>Scroll down through later batches. Expand groups, then click intersections to define exact coverage for each library.</small></div><div className="matrix-live-summary"><span>KNOWN FACTORS <strong>{knownFactorCount}</strong><small>{measuredFactorCount} report-observed dimensions</small></span><span>T0 SUBJECTS <strong>{tierZeroSubjects.length}</strong><small>{tierZeroGapCount} recipe or route gaps</small></span><span>DRAFT EXECUTIONS <strong>{desiredCellCount}</strong></span><span>QUEUEABLE <strong>{plannedCells}</strong><small>TOML intent</small></span><span>BUILT <strong>{builtExecutions}</strong><small>sealed evidence only</small></span><span>ARTIFACT ONLY <strong>{cells.filter(cell => cell.coverage === 'artifact-only').length}</strong></span></div></div>
          <div className="matrix-toolbar">
            <div className="matrix-layer-control"><span>SHOW</span>{(['both', 'plan', 'inventory'] as const).map(layer => <button key={layer} className={matrixLayer === layer ? 'active' : ''} onClick={() => setMatrixLayer(layer)}>{layer === 'both' ? 'Plan + built' : layer}</button>)}</div>
            <div className="matrix-executor-control"><span>WORKER POOL</span><button className="active warning" disabled>Library local</button><small>native + explicit local cross-build · no QEMU</small></div>
            <div className="matrix-fold-control"><button onClick={() => setCollapsedVariableGroups([])}>Expand variables</button><button onClick={() => setCollapsedVariableGroups(matrixVariableGroups.map(group => group.id))}>Collapse variables</button><button onClick={() => setCollapsedLibraryGroups([])}>Expand batches</button></div>
          </div>
          <div className="inline-warning matrix-warning">Local library execution keeps the pinned source archive, exact cross-toolchain, reviewed adapter, flags and target ABI. No virtual machine is booted.</div>
          <div className="matrix-scroll" role="region" aria-label="Library and build variable matrix" tabIndex={0}>
            <table className="crosspoint-table">
              <thead><tr className="matrix-group-head"><th className="matrix-corner matrix-order" rowSpan={2}>#</th><th className="matrix-corner matrix-library" rowSpan={2}>Libraries / match sets</th><th className="matrix-corner matrix-batch" rowSpan={2}>Batch / inventory</th>{displayedVariableGroups.map(group => <th colSpan={group.displayedOptions.length} key={group.id}><button onClick={() => toggleVariableGroup(group.id)} aria-expanded={!group.collapsed}><span>{group.collapsed ? '▸' : '▾'}</span>{group.label}<small>{group.collapsed ? `${group.options.length} hidden` : group.note}</small></button></th>)}</tr><tr className="matrix-variable-head">{displayedVariableGroups.flatMap(group => group.displayedOptions.map(column => <th key={column.id} className={column.kind === 'summary' ? 'summary-column' : ''}><span>{column.label}</span><small>{column.detail}</small></th>))}</tr></thead>
              <tbody>{libraryGroups.map((group, groupIndex) => {
                const collapsed = collapsedLibraryGroups.includes(group.id);
                const familyGroups = Array.from(new Set(group.rows.map(recipe => recipe.familyGroup)));
                const batch = rows.find(row => row.id === group.id);
                return <Fragment key={group.id}><tr className={batch?.tier === 'T0' ? 'matrix-batch-group tier-zero' : 'matrix-batch-group'}><th colSpan={3 + matrixColumnCount}><button onClick={() => toggleLibraryGroup(group.id)} aria-expanded={!collapsed}><span>{collapsed ? '▸' : '▾'}</span><b>{String(groupIndex + 1).padStart(2, '0')} · {batch?.tier ? `${batch.tier} · ` : ''}{group.id}</b><strong>{group.label}</strong><small>{group.note} · {group.rows.length} subject rows</small></button></th></tr>{!collapsed && !group.rows.length && <tr className="matrix-deferred-row"><th colSpan={3}>Later batch · no catalog rows loaded</th><td colSpan={matrixColumnCount}>This batch remains in priority order and will populate when its resolved match set is loaded.</td></tr>}{!collapsed && familyGroups.map(familyGroup => <Fragment key={`${group.id}-${familyGroup}`}><tr className="matrix-match-group"><th colSpan={3}><span>↳</span>{familyGroup}</th><td colSpan={matrixColumnCount}>{Array.from(new Set(group.rows.filter(recipe => recipe.familyGroup === familyGroup).map(recipe => recipe.matchSet))).join(' · ')}</td></tr>{group.rows.filter(recipe => recipe.familyGroup === familyGroup).map(recipe => {
                  const recipeSelected = selectedRecipes.includes(recipe.id);
                  const order = selectedRecipeRows.findIndex(row => row.id === recipe.id);
                  const recipeBatch = rows.find(row => row.id === recipe.batch);
                  return <tr className={recipeSelected ? 'matrix-library-row selected' : 'matrix-library-row'} key={recipe.id}><th className="matrix-order"><button onClick={() => toggleRecipe(recipe.id)} disabled={!recipe.planEligible} aria-pressed={recipeSelected} title={recipe.planEligible ? 'Add or remove this reviewed recipe from the queue draft' : 'Coverage subject is blocked until a reviewed recipe and route exist'}>{recipe.planEligible ? (recipeSelected ? String(order + 1).padStart(2, '0') : '+') : '!'}</button></th><th className="matrix-library"><div><strong>{recipe.name}</strong><em>{recipe.version}</em><small>{recipe.detail}</small></div><button onClick={() => setInspectedRecipe(recipe.id)}>{recipe.planEligible ? 'PROV' : 'GAP'}</button></th><th className="matrix-batch"><span className={`batch-status ${recipeBatch?.status.toLowerCase()}`}>{recipe.batch}</span><small>{recipeBatch?.status || 'assigned'}{recipeBatch?.status === 'Defined' ? ' · not submitted' : ''}</small><b className={`inventory-state ${recipe.readiness}`}>{recipe.coverage}</b></th>{displayedVariableGroups.flatMap(variableGroup => variableGroup.displayedOptions.map(column => {
                    const catalogOnly = !recipe.planEligible;
                    const routeRelevant = column.kind === 'route' && (
                      recipe.mode === 'native'
                        ? nativeRouteOptions.some(route => route.id === column.id)
                        : toolchainOptions.some(toolchain => (
                          toolchain.id === column.id
                          && toolchain.family === recipe.toolchainFamily
                          && (!recipe.toolchainVariants?.length || recipe.toolchainVariants.includes(toolchain.variant))
                        ))
                    );
                    const compatible = column.kind === 'summary'
                      || column.kind === 'catalog'
                      || (column.kind === 'route' && routeIsCompatible(recipe, column.id))
                      || (column.kind === 'factor' && recipe.mode === 'native' && recipe.planEligible);
                    const requested = recipeSelected && (column.kind === 'route' ? (routeSelections[recipe.id] || []).includes(column.id) : column.kind === 'factor' ? (factorSelections[recipe.id] || []).includes(column.id) : false);
                    const inventory = column.kind === 'route' && routeRelevant
                      ? inventoryForRoute(recipe, column.id)
                      : 'not-built';
                    const routeToken = toolchainOptions.find(toolchain => toolchain.id === column.id)?.variant;
                    const liveJob = column.kind === 'route' ? factory.snapshot?.jobs.find(job => (
                      cellMatchesRecipe(job.base_cell, recipe.name, recipe.version)
                      && (routeToken ? job.base_cell.includes(`:${routeToken}`) : job.base_cell.includes(`:${column.id}:`))
                    )) : undefined;
                    const unsupported = column.state === 'gap' || (column.kind === 'factor' && column.state !== 'registered');
                    let state = compatible || routeRelevant ? 'unbuilt' : 'unavailable';
                    if (column.kind === 'catalog') state = column.state;
                    else if (column.kind === 'summary') state = 'summary';
                    else if (column.kind === 'route' && routeRelevant && !compatible) state = 'blocked';
                    else if (catalogOnly && column.kind !== 'route') state = 'blocked';
                    else if (matrixLayer === 'inventory') state = inventory;
                    else if (requested && unsupported) state = 'blocked';
                    else if (matrixLayer === 'both' && inventory === 'built') state = 'built';
                    else if (matrixLayer === 'both' && inventory === 'artifact-only') state = 'artifact-only';
                    else if (requested && (liveJob?.state === 'running' || liveJob?.state === 'leased')) state = 'running';
                    else if (requested && liveJob?.state === 'queued') state = 'queued';
                    else if (requested && (liveJob?.state === 'blocked' || liveJob?.state === 'failed')) state = 'blocked';
                    else if (requested) state = 'selected';
                    const action = () => {
                      if (column.kind === 'summary') return toggleVariableGroup(variableGroup.id);
                      if (column.kind === 'catalog') return setInspectedFactor(column.id);
                      if (!compatible || catalogOnly) return setInspectedRecipe(recipe.id);
                      if (!recipeSelected) setSelectedRecipesOverride(current => [...(current ?? selectedRecipes), recipe.id]);
                      if (column.kind === 'route') toggleRoute(recipe.id, column.id);
                      else toggleFactor(recipe.id, column.id);
                    };
                    return <td className={`matrix-point-cell ${state}`} key={`${recipe.id}-${column.id}`}><button onClick={action} disabled={!compatible && !routeRelevant} aria-pressed={requested} title={`${recipe.name} × ${column.label}: ${catalogOnly && state === 'blocked' ? 'desired gap' : state}. ${catalogOnly ? recipe.gap : column.detail}`}><span>{state === 'unavailable' ? '—' : state === 'blocked' ? '!' : state === 'artifact-only' ? '◐' : state === 'built' ? '■' : state === 'running' ? '▶' : state === 'recorded' ? '●' : state === 'unmodeled' ? '?' : state === 'summary' ? (column.kind === 'summary' ? (variableGroup.options.filter(option => option.kind === 'catalog' || (option.kind === 'route' ? (routeSelections[recipe.id] || []).includes(option.id) : (factorSelections[recipe.id] || []).includes(option.id))).length || '·') : '·') : requested ? '■' : '·'}</span></button></td>;
                  }))}</tr>;
                })}</Fragment>)}</Fragment>;
              })}</tbody>
            </table>
          </div>
          <div className="matrix-legend"><span><i className="selected" /> selected</span><span><i className="queued" /> queued</span><span><i className="running" /> running</span><span><i className="built" /> sealed built</span><span><i className="artifact-only" /> artifact only</span><span><i className="blocked" /> blocked / desired gap</span><span><i className="unbuilt" /> unbuilt</span><span><i className="unavailable" /> incompatible</span><p>Built is evidence-backed; a completed batch alone does not imply that its artifact is still present.</p></div>
          {inspectedCatalogFactor && <aside className="matrix-factor-inspector"><div><span>KNOWN SENSITIVITY FACTOR</span><button onClick={() => setInspectedFactor(null)} aria-label="Close factor detail">×</button></div><h3>{inspectedCatalogFactor.label}</h3><p>{inspectedCatalogFactor.detail}</p><dl><div><dt>Catalogue ID</dt><dd>{inspectedCatalogFactor.id}</dd></div><div><dt>Group</dt><dd>{inspectedFactorGroup?.label || 'Sensitivity'}</dd></div><div><dt>Matrix status</dt><dd>{inspectedCatalogFactor.state === 'recorded' ? 'Recorded in resolved-cell provenance' : 'Known factor; no named selectable variant yet'}</dd></div><div><dt>Authority</dt><dd>sensitivity/factors.toml</dd></div></dl><small>The catalogue is intentionally extensible: report-backed factors are the current baseline, not a claim that every possible FID influence is already known.</small></aside>}
          {inspected && <aside className="recipe-provenance matrix-provenance"><div><span>{inspected.planEligible ? 'REVIEWED RECIPE PROVENANCE' : 'TIER 0 COVERAGE GAP'}</span><button onClick={() => setInspectedRecipe(null)} aria-label="Close provenance">×</button></div><h3>{inspected.name} <em>{inspected.version}</em></h3><p>{inspected.planEligible ? 'Immutable build identity comes from the reviewed recipe. Change the recipe TOML and re-resolve the plan to alter these fields.' : inspected.gap}</p><dl><div><dt>Authority</dt><dd>{inspected.authority}</dd></div><div><dt>Readiness</dt><dd>{inspected.coverage}</dd></div><div><dt>Batch / family</dt><dd>{inspected.batch} / {inspected.familyGroup}</dd></div><div><dt>Match context</dt><dd>{inspected.matchSet}</dd></div>{inspected.recipePath && <div><dt>Recipe</dt><dd>{inspected.recipePath}</dd></div>}{inspected.adapter && <div><dt>Mode / adapter</dt><dd>{inspected.mode} / {inspected.adapter}</dd></div>}{inspected.url && <div className="wide"><dt>Source URL</dt><dd>{inspected.url}</dd></div>}{inspected.sha256 && <div className="wide"><dt>SHA-256</dt><dd>{inspected.sha256}</dd></div>}</dl></aside>}
        </section>

        <aside className="plan-visualizer">
          <section className="panel cell-map-panel">
            <div className="panel-header"><div><p className="panel-kicker">RESOLVED EXECUTION MAP</p><h3>{cells.length} base cells → {desiredCellCount} exact executions</h3></div><span className={blockedCells ? 'plan-state blocked' : 'plan-state ready'}>{blockedCells ? `${blockedCells} GAP` : 'COVERED'}</span></div>
            <div className="cell-summary"><div><span>DESIRED</span><strong>{desiredCellCount}</strong></div><div><span>QUEUEABLE</span><strong>{plannedCells}</strong></div><div><span>BLOCKED</span><strong>{blockedCells}</strong></div><div><span>OPTIONS</span><strong>{selectedFactorRows.length} / {allFactorOptions.length}</strong></div></div>
            <div className="cell-flow-head"><span>Recipe</span><span>Target + toolchain</span><span>Treatment</span><span>Analysis</span></div>
            <div className="visual-cell-list">
              {cells.map(cell => <div className={`visual-cell ${cell.status} ${cell.coverage || 'not-built'}`} key={cell.id}><span className="cell-status-icon">{cell.coverage === 'artifact-only' ? '◐' : cell.status === 'planned' ? '✓' : '!'}</span><div><strong>{cell.recipe}</strong><small>{cell.coverage === 'artifact-only' ? `artifact found · ${cell.batch}` : `${cell.route} · ${cell.batch}`}</small></div><b>→</b><div><strong>{cell.target}</strong><small>{cell.toolchain}</small></div><b>→</b><div><strong>{cell.treatment}</strong><small>× {combinationsForRecipe(cell.recipeId).length} exact factor tuples</small></div><b>→</b><div><strong>{cell.analysis}</strong><small>execution identity recorded</small></div></div>)}
              {!cells.length && <div className="empty-state"><span>◇</span><strong>No desired cells</strong><p>Select at least one recipe and compatible route.</p></div>}
            </div>
            {blockedCells > 0 && <div className="coverage-alert"><span>!</span><p><strong>Desired coverage is not silently discarded.</strong><small>{blockedCells} desired cells currently lack a registered treatment, source-capable toolchain, or guarded truth/admission path. They remain visible until those requirements exist.</small></p></div>}
          </section>

          <section className="panel malware-estimate-panel"><div className="panel-header"><div><p className="panel-kicker">TIMING EVIDENCE</p><h3>Ground-truth workload</h3></div><span className={timing?.eta ? 'plan-state ready' : 'plan-state'}>{timing?.eta ? 'MEASURED' : 'COLLECTING'}</span></div>{malwareRecipe ? <div className="malware-estimate-row"><span className="malware-glyph">M</span><div><strong>{malwareRecipe.name}</strong><small>{malwareRecipe.version} · {malwareRecipe.adapter}</small></div><p><span>KNOWN CELLS</span><strong>{malwareInventory.length}</strong></p><p><span>SEALED / LOOSE</span><strong>{malwareInventory.filter(([, row]) => row.state === 'built').length} / {malwareInventory.filter(([, row]) => row.state === 'artifact-only').length}</strong></p><p><span>QUEUE ETA</span><strong>{measuredEtaNs === null ? 'Collecting evidence' : formatDurationNs(measuredEtaNs)}</strong><small>{timing?.eta?.sample_count ? `${timing.eta.sample_count} measured workflows` : 'no historical estimate yet'}</small></p></div> : <div className="empty-state"><span>◇</span><strong>No reviewed ground-truth recipe</strong><p>Add one to the recipe authority before planning it.</p></div>}<div className="estimate-note"><span>i</span><p><strong>No formula-based ETA is shown.</strong><small>An estimate appears only when the coordinator returns evidence-backed timing data with a sample count. Matrix selections remain planning intent until synchronized into the queue.</small></p></div></section>

          <section className="panel execution-queue-panel"><div className="panel-header"><div><p className="panel-kicker">PRIORITY QUEUE DRAFT</p><h3>Batch order × base cell × variance</h3></div><span className="plan-state">TOML INTENT</span></div><div className="queue-controls single"><label><span>VARIANCE ORDER WITHIN EACH BATCH</span><select value={queueStrategy} onChange={event => setQueueStrategyOverride(event.target.value)}><option value="recipe-then-variant">recipe, then variance</option><option value="variant-then-recipe">variance, then recipe</option></select></label><button onClick={() => setQueueMessage(`Priority queue draft updated with ${executionQueue.length} execution identities in current batch order.`)}>Update priority queue draft</button></div>{queueMessage && <div className="queue-message">✓ {queueMessage}</div>}<div className="queue-state-summary"><div><span>QUEUEABLE</span><strong>{executionQueue.filter(row => row.state === 'queueable').length}</strong></div><div><span>BUILT</span><strong>{builtExecutions}</strong></div><div><span>ARTIFACT ONLY</span><strong>{cells.filter(cell => cell.coverage === 'artifact-only').length}</strong></div><div><span>UNBUILT / BLOCKED</span><strong>{executionQueue.filter(row => row.state === 'blocked').length}</strong></div></div><div className="execution-queue-list">{executionQueue.slice(0, 8).map(row => <div className={`execution-queue-row ${row.state}`} key={`${row.cell.id}-${row.position}`}><b>{String(row.position).padStart(3, '0')}</b><div><strong>{row.cell.recipe}</strong><small>{row.cell.target} · {row.combination.map(option => option.label).join(' / ') || 'route defaults'}</small></div><em>{row.cell.batch}</em><span>{row.cell.coverage === 'built' ? 'built' : row.cell.coverage === 'artifact-only' ? 'artifact only' : row.state}</span></div>)}{executionQueue.length > 8 && <div className="queue-remainder">+ {executionQueue.length - 8} more ordered execution identities</div>}</div><div className="estimate-note"><span>i</span><p><strong>Batch priority is read from plans/priority-queue.toml.</strong><small>The synchronized ledger owns queued, leased, running and complete state. Change reviewed TOML intent, synchronize it through the API or CLI, then let workers follow the durable order.</small></p></div></section>

          {tomlOpen && <section className="panel toml-panel"><div className="panel-header"><div><p className="panel-kicker">VALIDATED REQUEST DRAFT</p><h3>Equivalent TOML</h3></div><span className={draftIsCurrent ? 'plan-state ready' : 'plan-state'}>{draftIsCurrent ? 'RESOLVED' : 'DRAFT'}</span></div><pre>{toml}</pre><div className="draft-controls"><label><span>DRAFT NAME</span><input value={draftName} onChange={event => { setDraftName(event.target.value); setDraftMessage('Draft changed; resolve it again before saving.'); }} spellCheck={false} /></label><div><button onClick={() => void resolveDraft()} disabled={factory.busyAction !== null || !plannedRecipeRows.length}>{factory.busyAction === 'plan-draft-resolve' ? 'Resolving…' : 'Resolve against authority'}</button><button className="primary" onClick={() => void saveDraft()} disabled={factory.busyAction !== null || !draftIsCurrent}>{factory.busyAction === 'plan-draft-save' ? 'Saving…' : savedAuthorityDraft || savedDraftSha256 ? 'Save validated update' : 'Save validated draft'}</button></div><p className={draftIsCurrent ? 'valid' : ''}>{draftResult && !draftIsCurrent ? 'Draft changed; resolve it again before saving.' : draftMessage}</p></div><div className="toml-footer"><span>Only catalog identities are accepted; saving does not enqueue or execute the plan</span><code>{savedAuthorityDraft?.path ?? 'plans/drafts/&lt;name&gt;.toml'}</code></div></section>}
        </aside>
      </div>
    </div>
  );
}

function TimingView({ factory }: { factory: FactoryApiState }) {
  const snapshot = factory.snapshot;
  const timing = factory.timings;
  const snapshotSpans = snapshot?.stage_attempts ?? [];
  const recentSpans = timing?.recent ?? snapshotSpans;
  const activeSpans = snapshotSpans.filter(
    span => span.state === 'started' && span.ended_at === null,
  );
  const measuredRecent = recentSpans
    .filter(span => (
      span.state === 'completed'
      && span.duration_ns !== null
      && span.duration_source === 'worker-monotonic'
    ))
    .sort((left, right) => right.stage_attempt_id - left.stage_attempt_id)
    .slice(0, 10);
  const attempts = snapshot?.attempts ?? [];
  const retryOrFailureAttempts = attempts
    .filter(attempt => (
      attempt.attempt_number > 1
      || attempt.state === 'failed'
      || attempt.state === 'expired'
    ))
    .sort((left, right) => Date.parse(right.started_at) - Date.parse(left.started_at));
  const failedSpans = recentSpans
    .filter(span => ['failed', 'interrupted'].includes(span.state))
    .sort((left, right) => right.stage_attempt_id - left.stage_attempt_id);
  const regressedClockSpans = recentSpans
    .filter(span => span.wall_clock_regressed && !['failed', 'interrupted'].includes(span.state))
    .sort((left, right) => right.stage_attempt_id - left.stage_attempt_id);
  const resourceSpans = recentSpans
    .filter(span => span.state === 'completed' && (
      numericMetric(span, 'self_max_rss_bytes_peak') !== null
      || numericMetric(span, 'child_max_rss_bytes_peak') !== null
      || numericMetric(span, 'process_cpu_duration_ns') !== null
    ))
    .sort((left, right) => right.stage_attempt_id - left.stage_attempt_id)
    .slice(0, 10);
  const [now, setNow] = useState(() => Date.now());
  const generatedAt = timing ? Date.parse(timing.generated_at) : Number.NaN;
  const coordinatorNow = Number.isFinite(generatedAt) && factory.lastUpdated
    ? generatedAt + Math.max(0, now - factory.lastUpdated.getTime())
    : now;

  useEffect(() => {
    if (!activeSpans.length) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [activeSpans.length]);

  const eta = timing?.eta ?? null;
  const etaP50 = etaDuration(eta);
  const etaP90 = eta && typeof eta.p90_remaining_duration_ns === 'number'
    ? eta.p90_remaining_duration_ns
    : null;
  const etaEvidence = eta !== null && (eta.sample_count ?? 0) > 0;
  const completedSamples = timing?.sample_counts.completed_stage_spans ?? 0;
  const workflowSamples = timing?.sample_counts.completed_workflows ?? 0;
  const throughput = timing?.throughput;
  const timingState = factory.timingsError
    ? 'Timing endpoint unavailable'
    : timing
      ? completedSamples
        ? 'Measured ledger evidence'
        : 'Collecting first completed spans'
      : 'Waiting for coordinator';

  return <div className="view-stack timing-view">
    <ViewIntro
      kicker="MEASURED EXECUTION"
      title="Timing, throughput and ETA evidence"
      copy="Every active and completed stage is tied to a fenced attempt. Percentiles use completed worker-monotonic spans only; interrupted or coordinator-derived durations remain visible for diagnosis but never enter stage p50/p90."
      action={<button className="secondary-action" disabled>{timingState}</button>}
    />

    <section className="timing-metrics" aria-label="Timing evidence summary">
      <article className="panel timing-metric"><span>ACTIVE STAGES</span><strong>{activeSpans.length}</strong><small>{activeSpans.length ? 'elapsed clocks updating live' : 'nothing executing'}</small></article>
      <article className="panel timing-metric"><span>COMPLETED STAGE SAMPLES</span><strong>{completedSamples}</strong><small>{workflowSamples} complete workflow {workflowSamples === 1 ? 'sample' : 'samples'}</small></article>
      <article className="panel timing-metric"><span>SUCCESSFUL-ATTEMPT SERVICE RATE</span><strong>{throughput ? `${throughput.service_jobs_per_hour.toFixed(2)} / h` : 'Collecting'}</strong><small>{throughput ? `${throughput.sample_count} final-attempt ${throughput.sample_count === 1 ? 'sample' : 'samples'} · excludes retries, queue, idle and concurrency` : 'no defensible service-rate proxy yet'}</small></article>
      <article className="panel timing-metric"><span>QUEUE ETA</span><strong>{etaEvidence && etaP50 !== null ? formatDurationNs(etaP50) : 'Collecting'}</strong><small>{etaEvidence ? `${eta.sample_count} samples${eta.confidence ? ` · ${eta.confidence}` : ''}` : 'shown only when returned by the timing API'}</small></article>
    </section>

    {factory.timingsError && <div className="inline-warning">The queue API is live, but timing aggregation is not available yet: {factory.timingsError}</div>}
    {timing?.aggregates_truncated && <div className="inline-warning">Timing distributions use the most recent global window of {timing.aggregate_sample_limit} stage/workflow samples. Rare stages outside that window may not appear; raw recent evidence remains available in the ledger.</div>}

    <section className="timing-live-grid">
      <article className="panel timing-table-panel">
        <div className="panel-header"><div><p className="panel-kicker">LIVE ATTEMPTS</p><h3>Current stage elapsed time</h3></div><span className={activeSpans.length ? 'timing-live-badge' : 'timing-muted-badge'}>{activeSpans.length ? 'LIVE' : 'IDLE'}</span></div>
        <div className="timing-table timing-active-table">
          <div className="timing-table-head"><span>Attempt</span><span>Stage</span><span>Worker</span><span>Started</span><span>Elapsed</span></div>
          {activeSpans.map(span => {
            const job = snapshot?.jobs.find(candidate => candidate.job_id === span.job_id);
            return <div className="timing-table-row active" key={span.stage_attempt_id}><span><strong>{job?.base_cell ?? span.job_id.slice(0, 12)}</strong><small>attempt {span.attempt_number} · stage run {span.stage_attempt}</small></span><span><strong>{stageLabel(span.stage)}</strong><small>sequence {span.sequence}</small></span><code>{span.worker_id}</code><time>{formatStartedAt(span.started_at)}</time><b>{formatDurationNs(elapsedNs(span.started_at, coordinatorNow))}</b></div>;
          })}
          {!activeSpans.length && <div className="empty-state timing-empty"><span>◇</span><strong>No active stage</strong><p>The live clock appears as soon as a worker starts a measured stage.</p></div>}
        </div>
      </article>

      <article className="panel timing-table-panel">
        <div className="panel-header"><div><p className="panel-kicker">RECENT MEASUREMENTS</p><h3>Completed worker-monotonic spans</h3></div><span className="timing-muted-badge">LAST {measuredRecent.length}</span></div>
        <div className="timing-recent-list">
          {measuredRecent.map(span => <div key={span.stage_attempt_id}><span className="timing-stage-glyph">{span.sequence}</span><p><strong>{stageLabel(span.stage)}</strong><small>{span.job_id.slice(0, 12)} · attempt {span.attempt_number} · {span.worker_id}</small></p><b>{formatDurationNs(span.duration_ns)}</b></div>)}
          {!measuredRecent.length && <div className="empty-state timing-empty"><span>◇</span><strong>Collecting stage evidence</strong><p>Completed monotonic spans will appear here; estimated and interrupted values are excluded.</p></div>}
        </div>
      </article>
    </section>

    <section className="timing-aggregate-grid">
      <article className="panel timing-table-panel">
        <div className="panel-header"><div><p className="panel-kicker">STAGE DISTRIBUTIONS</p><h3>Measured p50 / p90 by stage</h3></div><span className="timing-source-badge">WORKER MONOTONIC</span></div>
        <div className="timing-distribution-table">
          <div className="timing-distribution-head"><span>Stage</span><span>Samples</span><span>p50</span><span>p90</span><span>Mean</span><span>Range</span></div>
          {(timing?.stages ?? []).flatMap(row => row.sample_count > 0 && row.duration_ns ? [<div className="timing-distribution-row" key={row.stage}><strong>{stageLabel(row.stage)}</strong><span>{row.sample_count}</span><b>{formatDurationNs(row.duration_ns.p50)}</b><b>{formatDurationNs(row.duration_ns.p90)}</b><span>{formatDurationNs(row.duration_ns.mean)}</span><small>{formatDurationNs(row.duration_ns.min)} – {formatDurationNs(row.duration_ns.max)}</small></div>] : [])}
          {!(timing?.stages ?? []).some(row => row.sample_count > 0 && row.duration_ns) && <div className="empty-state timing-empty"><span>◇</span><strong>No completed stage distribution</strong><p>p50 and p90 require completed worker-monotonic samples.</p></div>}
        </div>
      </article>

      <article className="panel timing-table-panel">
        <div className="panel-header"><div><p className="panel-kicker">WORKFLOW DISTRIBUTIONS</p><h3>Attempt service and queue wait</h3></div><span className="timing-source-badge wall">COORDINATOR CLOCK</span></div>
        <div className="timing-workflow-table">
          <div className="timing-workflow-head"><span>Workflow</span><span>Samples</span><span>Service p50</span><span>Service p90</span><span>Queue wait p50</span><span>Queue wait p90</span></div>
          {(timing?.workflows ?? []).flatMap(row => row.sample_count > 0 && row.duration_ns ? [<div className="timing-workflow-row" key={row.workflow}><strong>{row.workflow}</strong><span>{row.sample_count}</span><b>{formatDurationNs(row.duration_ns.p50)}</b><b>{formatDurationNs(row.duration_ns.p90)}</b><span>{formatDurationNs(row.queue_wait_duration_ns?.p50)}</span><span>{formatDurationNs(row.queue_wait_duration_ns?.p90)}</span></div>] : [])}
          {!(timing?.workflows ?? []).some(row => row.sample_count > 0 && row.duration_ns) && <div className="empty-state timing-empty"><span>◇</span><strong>No completed workflow distribution</strong><p>Queue wait appears only when the coordinator can derive a defensible boundary.</p></div>}
        </div>
        {(timing?.workflows ?? []).some(row => row.queue_wait_basis) && <p className="timing-basis-note">Queue wait uses coordinator wall-clock boundaries and may include disarmed, paused and readiness time; the basis is preserved with the aggregate.</p>}
      </article>
    </section>

    <section className="timing-bottom-grid">
      <article className="panel timing-table-panel">
        <div className="panel-header"><div><p className="panel-kicker">RESOURCE EVIDENCE</p><h3>CPU, peak RSS and operation counts</h3></div><span className="timing-source-badge">MEASURED SPANS</span></div>
        <div className="timing-diagnostic-list">
          {resourceSpans.map(span => {
            const evidence = resourceEvidence(span);
            return <div key={`resource-${span.stage_attempt_id}`}><span className="timing-stage-glyph">R</span><p><strong>{stageLabel(span.stage)}</strong><small>CPU {formatDurationNs(evidence.cpu)} · peak RSS {formatBytes(evidence.rss)}{evidence.details ? ` · ${evidence.details}` : ''}</small></p><b>{formatDurationNs(span.duration_ns)}</b></div>;
          })}
          {!resourceSpans.length && <div className="empty-state timing-empty"><span>◇</span><strong>No resource samples yet</strong><p>CPU and peak-RSS evidence appears after measured library stages complete.</p></div>}
        </div>
        <p className="timing-basis-note">RSS is a process/child peak reading, not a per-span delta or live utilization percentage. Use several representative compile and Ghidra spans before changing worker capacity.</p>
      </article>

      <article className="panel timing-table-panel">
        <div className="panel-header"><div><p className="panel-kicker">RETRIES & FAILURES</p><h3>Attempt and stage diagnostics</h3></div><span className={retryOrFailureAttempts.length || failedSpans.length || regressedClockSpans.length ? 'timing-warning-badge' : 'timing-muted-badge'}>{retryOrFailureAttempts.length + failedSpans.length + regressedClockSpans.length}</span></div>
        <div className="timing-diagnostic-list">
          {retryOrFailureAttempts.slice(0, 8).map(attempt => <AttemptTimingRow attempt={attempt} now={coordinatorNow} key={`attempt-${attempt.attempt_id}`} />)}
          {failedSpans.slice(0, 8).map(span => <div key={`span-${span.stage_attempt_id}`}><span className={`timing-result ${span.state}`}>{span.state}</span><p><strong>{stageLabel(span.stage)}</strong><small>{span.job_id.slice(0, 12)} · attempt {span.attempt_number} · {span.duration_source ?? 'no duration source'}</small></p><b>{formatDurationNs(span.duration_ns)}</b></div>)}
          {regressedClockSpans.slice(0, 8).map(span => <div key={`clock-${span.stage_attempt_id}`}><span className="timing-result interrupted">clock</span><p><strong>{stageLabel(span.stage)}</strong><small>{span.job_id.slice(0, 12)} · UTC boundary regressed; monotonic duration remains authoritative</small></p><b>{formatDurationNs(span.duration_ns)}</b></div>)}
          {!retryOrFailureAttempts.length && !failedSpans.length && !regressedClockSpans.length && <div className="empty-state timing-empty"><span>✓</span><strong>No retry or failure timing</strong><p>This is an empty evidence set, not a claim that production runs have succeeded.</p></div>}
        </div>
      </article>

      <article className="panel timing-eta-panel">
        <div className="panel-header"><div><p className="panel-kicker">EVIDENCE-BASED ETA</p><h3>Current queue projection</h3></div><span className={etaEvidence ? 'timing-source-badge' : 'timing-muted-badge'}>{etaEvidence ? 'AVAILABLE' : 'COLLECTING'}</span></div>
        {etaEvidence ? <div className="timing-eta-body"><div><span>p50 remaining</span><strong>{formatDurationNs(etaP50)}</strong></div><div><span>p90 remaining</span><strong>{formatDurationNs(etaP90)}</strong></div><div><span>Sample count</span><strong>{eta.sample_count}</strong></div><div><span>Confidence</span><strong>{eta.confidence ?? 'not labelled'}</strong></div>{eta.projected_completion_at && <p>Projected completion: <b>{formatStartedAt(eta.projected_completion_at)}</b></p>}</div> : <div className="empty-state timing-empty eta"><span>⌁</span><strong>Collecting evidence</strong><p>The UI will not estimate completion from cell counts or a fixed multiplier. ETA appears only when the coordinator returns a measured model and sample count.</p></div>}
      </article>
    </section>
  </div>;
}

function AttemptTimingRow({ attempt, now }: { attempt: CoordinatorAttempt; now: number }) {
  return <div><span className={`timing-result ${attempt.state}`}>{attempt.attempt_number > 1 ? `retry ${attempt.attempt_number}` : attempt.state}</span><p><strong>{attempt.job_id.slice(0, 12)}</strong><small>{attempt.worker_id} · {formatStartedAt(attempt.started_at)}{attempt.queue_wait_duration_ns !== undefined && attempt.queue_wait_duration_ns !== null ? ` · waited ${formatDurationNs(attempt.queue_wait_duration_ns)}` : ''}</small></p><b>{formatDurationNs(elapsedNs(attempt.started_at, now, attempt.ended_at))}</b></div>;
}

function BatchesView({ onNewBatch, batchOrder, setBatchOrder, rows, live }: { onNewBatch: () => void; batchOrder: string[]; setBatchOrder: React.Dispatch<React.SetStateAction<string[]>>; rows: BatchRow[]; live: boolean }) {
  const batches = batchOrder.map(id => rows.find(batch => batch.id === id)).filter((batch): batch is BatchRow => Boolean(batch));
  const batchStatusCounts = (status: BatchRow['status']) => batches.filter(batch => batch.status === status).length;
  const moveBatch = (id: string, direction: -1 | 1) => setBatchOrder(current => {
    const ordered = current.length ? current : batches.map(batch => batch.id);
    const from = ordered.indexOf(id);
    const to = from + direction;
    if (from < 0 || to < 0 || to >= ordered.length) return ordered;
    const next = [...ordered];
    [next[from], next[to]] = [next[to], next[from]];
    return next;
  });
  return <div className="view-stack">
    <ViewIntro kicker="BATCH OPERATIONS" title="Priority queue and execution ledger" copy={live ? 'Live order and state come from the synchronized plans/priority-queue.toml ledger. Edit and review TOML to change priority; the viewer never silently mutates queue intent.' : 'Preview order only. The CLI authority is plans/priority-queue.toml; connect the local API to read the durable execution ledger.'} action={<button className="primary-action" onClick={onNewBatch}>Open matrix draft</button>} />
    <section className="panel data-panel">
      <div className="filterbar"><button className="filter active">All <span>{batches.length}</span></button><button className="filter">Defined <span>{batchStatusCounts('Defined')}</span></button><button className="filter">Running <span>{batchStatusCounts('Running')}</span></button><button className="filter">Blocked <span>{batchStatusCounts('Blocked')}</span></button><button className="filter">Queued <span>{batchStatusCounts('Queued')}</span></button><button className="filter">Complete <span>{batchStatusCounts('Complete')}</span></button><div className="filter-search">⌕&nbsp; Filter batches</div></div>
      <div className="batch-table">
        <div className="batch-head"><span>Priority / batch</span><span>Status</span><span>Progress</span><span>Worker</span><span>Route</span><span>ETA</span><span>Order</span></div>
        {batches.map((batch, index) => <div className="batch-row" key={batch.id}>
          <div><strong><em>{String(index + 1).padStart(2, '0')}</em>{batch.tier ? `${batch.tier} · ` : ''}{batch.id}</strong><small>{batch.name}{batch.note ? ` · ${batch.note}` : ''}</small></div><span className={`batch-status ${batch.status.toLowerCase()}`}>{batch.status}{batch.status === 'Defined' ? ' · disarmed' : ''}</span>
          <div className="table-progress"><div><span style={{width: `${batch.percent}%`}} /></div><small>{batch.progress}</small></div><span>{batch.worker}</span><code>{batch.route}</code><strong className="eta">{batch.eta}</strong><div className="batch-order-buttons"><button disabled={live || index === 0} onClick={() => moveBatch(batch.id, -1)} aria-label={`Raise ${batch.id} priority`}>↑</button><button disabled={live || index === batches.length - 1} onClick={() => moveBatch(batch.id, 1)} aria-label={`Lower ${batch.id} priority`}>↓</button></div>
        </div>)}
      </div>
    </section>
  </div>;
}

function ToolchainsView({ factory }: { factory: FactoryApiState }) {
  const inventory = factory.capabilities?.toolchains.entries ?? [];
  const pool = factory.capabilities?.worker_pools['library-local'];
  const sourceRows = inventory.filter(row => row.capabilities.includes('source'));
  return <div className="view-stack">
    <ViewIntro kicker="LIVE CAPABILITY REGISTRY" title="Toolchain coverage for the library-local pool" copy="Detection is read-only. It distinguishes installed host tools, checksum-verified cached archives, exact queue eligibility, and unmet acquisition; QEMU and malware are excluded from this pool." action={<button className="primary-action" onClick={() => void factory.refresh()} disabled={factory.connection === 'connecting'}>{factory.connection === 'live' ? 'Scan again' : 'Retry connection'}</button>} />
    {factory.error && <div className="toast warning" role="status">! {factory.error}</div>}
    <section className="toolchain-summary">
      <article><span>REGISTRY ROWS</span><strong>{factory.capabilities ? inventory.length : '—'}</strong><small>reviewed pinned identities</small></article><article><span>SOURCE ROUTES</span><strong>{factory.capabilities ? sourceRows.length : '—'}</strong><small>local cross-build capable</small></article><article className="warn"><span>NEEDS SETUP</span><strong>{pool ? pool.eligible_jobs - pool.ready_now : '—'}</strong><small>active queue jobs</small></article><article><span>ACTIVE LEASES</span><strong>{pool?.active_workers ?? '—'}</strong><small>of {pool?.max_workers ?? '—'} current cap</small></article>
    </section>
    <section className="panel data-panel">
      <div className="filterbar"><button className="filter active">All variants</button><button className="filter">Source capable</button><button className="filter">Unmet</button><div className="filter-search">⌕&nbsp; Search variant or ABI</div></div>
      <div className="toolchain-table">
        <div className="toolchain-head"><span>Variant</span><span>Family</span><span>Target ABI</span><span>Evidence</span><span>Workers</span><span>Action</span></div>
        {inventory.map(row => {
          const tone = row.state === 'verified-cached' ? 'ready' : row.state === 'broken' ? 'warning' : 'cold';
          return <div className="toolchain-row" key={row.id}><div><span className={`cap-dot ${tone}`} /><strong>{row.variant}</strong></div><span>{row.family} {row.version}</span><code>{row.target.elf_class}-bit · {row.target.endianness}</code><span className={`evidence-badge ${tone}`}>{row.state}</span><strong>{row.capabilities.join(' + ')}</strong><button disabled>{row.state === 'missing' ? 'Needed' : 'Inspect'}</button></div>;
        })}
        {!inventory.length && <div className="empty-state"><span>◇</span><strong>No live toolchain inventory</strong><p>Start the loopback API service, then scan again.</p></div>}
      </div>
    </section>
  </div>;
}

function EvidenceView({ snapshot }: { snapshot: CoordinatorSnapshot | null }) {
  const completed = snapshot?.jobs.filter(job => job.state === 'complete' && job.result) ?? [];
  const selected = completed[0];
  const selectedResult = selected?.result ?? {};
  const artifacts = completed.flatMap(job => {
    if (!job.result) return [];
    return ['fidb', 'fidbf', 'seal'].flatMap(kind => {
      const value = job.result?.[kind];
      if (!value || typeof value !== 'object') return [];
      const record = value as Record<string, unknown>;
      if (typeof record.path !== 'string' || typeof record.sha256 !== 'string') return [];
      return [{ kind, path: record.path, sha256: record.sha256, job }];
    });
  });
  return <div className="view-stack">
    <ViewIntro kicker="SEALED PROVENANCE" title="Evidence remains readable files" copy="Only artifacts attached to completed, fenced ledger jobs appear here. Paths and hashes come from the coordinator result; a batch label alone never implies that evidence exists." action={<button className="secondary-action" disabled>{snapshot ? `${artifacts.length} artifacts` : 'Coordinator offline'}</button>} />
    <div className="evidence-layout">
      <section className="panel artifact-list"><div className="panel-header"><div><p className="panel-kicker">LEDGER OUTPUT SET</p><h3>Sealed library artifacts</h3></div><span className="plan-state">LIVE</span></div>
        {artifacts.map(artifact => <button className="artifact-row" key={`${artifact.job.job_id}-${artifact.kind}`}><span className="file-glyph">{artifact.kind.toUpperCase()}</span><div><strong>{artifact.path.split('/').pop()}</strong><small>{artifact.job.base_cell}</small></div><span>{artifact.kind === 'fidbf' ? 'Raw FID export' : artifact.kind === 'fidb' ? 'FID database' : 'Provenance seal'}</span><code>{artifact.sha256.slice(0, 16)}…</code><b>→</b></button>)}
        {!artifacts.length && <div className="empty-state"><span>◇</span><strong>No sealed queue artifacts yet</strong><p>Disarmed or unfinished jobs do not create evidence entries.</p></div>}
      </section>
      <section className="panel provenance-card"><div className="panel-header"><div><p className="panel-kicker">SELECTED CELL</p><h3>{selected?.base_cell ?? 'No completed cell'}</h3></div><span className={`worker-state ${selected ? 'ready' : 'offline'}`}>{selected ? 'Sealed' : 'Empty'}</span></div>
        {selected ? <><dl><div><dt>Job</dt><dd className="digest">{selected.job_id}</dd></div><div><dt>Batch</dt><dd>{selected.batch_id}</dd></div><div><dt>Attempts</dt><dd>{selected.attempt_count}</dd></div><div><dt>Worker</dt><dd>{selected.leased_by ?? 'released after seal'}</dd></div><div><dt>Executor</dt><dd>{typeof selectedResult.executor === 'string' ? selectedResult.executor : 'recorded in seal'}</dd></div><div><dt>State</dt><dd>{selected.state}</dd></div></dl><div className="cli-preview"><span>RESULT AUTHORITY</span><code>SQLite ledger + artifacts/runs/{selected.job_id}/…</code></div></> : <div className="empty-state"><span>◇</span><strong>Nothing to inspect</strong><p>Complete a library cell through the worker before provenance is shown.</p></div>}
      </section>
    </div>
  </div>;
}

function AutomationView({ factory }: { factory: FactoryApiState }) {
  const snapshot = factory.snapshot;
  const pool = factory.capabilities?.worker_pools['library-local'];
  const preflight = factory.preflight;
  const schedulePolicy = preflight?.policy.schedule;
  const startWindow = typeof schedulePolicy?.start === 'string' ? schedulePolicy.start : '—';
  const stopClaiming = typeof schedulePolicy?.stop_claiming === 'string' ? schedulePolicy.stop_claiming : '—';
  const hardCutoff = typeof schedulePolicy?.hard_cutoff === 'string' ? schedulePolicy.hard_cutoff : '—';
  const control = snapshot?.paused
    ? { label: 'Resume claims', action: factory.resume }
    : snapshot?.armed
      ? { label: 'Pause new claims', action: () => factory.pause('operator pause from control panel') }
      : { label: 'Synchronize queue', action: factory.sync };
  return <div className="view-stack">
    <ViewIntro kicker="UNATTENDED OPERATION" title="Automatic local-library worker" copy="The live coordinator can synchronize, pause, and resume the TOML-authoritative library queue. Arming remains an explicit reviewed TOML change; this GUI cannot start a build or widen the pool to QEMU or malware." action={<button className="secondary-action" onClick={() => void control.action()} disabled={factory.busyAction !== null}>{factory.busyAction ? 'Working…' : control.label}</button>} />
    {factory.error && <div className="toast warning" role="alert">! {factory.error}</div>}
    <div className="automation-layout">
      <section className="panel automation-form">
        <div className="panel-header"><div><p className="panel-kicker">TOML AUTHORITY</p><h3>plans/priority-queue.toml</h3></div><span className={`plan-state ${snapshot?.armed && !snapshot.paused ? 'ready' : ''}`}>{snapshot?.status.toUpperCase() ?? 'NOT SYNCED'}</span></div>
        <div className="policy-body">
          <label className="field-label">Enforced overnight policy</label><div className="mode-grid"><button className="selected" disabled><span>Night</span><small>all configured days</small></button><button disabled><span>{preflight?.schedule.claims_allowed ? 'Claims open' : 'Claims closed'}</span><small>{preflight?.schedule.reason ?? 'not evaluated'}</small></button><button disabled><span>Morning</span><small>hard cutoff {hardCutoff}</small></button><button disabled><span>{preflight?.resources.passed ? 'Host ready' : 'Host gated'}</span><small>measured before claim</small></button></div>
          <div className="section-divider" />
          <div className="two-fields"><label><span>Start claiming · TOML</span><input type="text" value={startWindow} readOnly /></label><label><span>Stop claiming / hard cutoff · TOML</span><input type="text" value={`${stopClaiming} / ${hardCutoff}`} readOnly /></label></div>
          <div className="two-fields"><label><span>Maximum active leases · TOML</span><input type="number" value={snapshot?.max_workers ?? 2} readOnly /></label><label><span>Retry ceiling · TOML</span><input type="number" value={snapshot?.max_attempts ?? 3} readOnly /></label></div>
          <div className="toggle-list">
            <label><div><strong>Library-local pool only</strong><small>Native, explicitly local source-library, and pinned archive-extraction routes. QEMU and malware are excluded.</small></div><input type="checkbox" checked readOnly /></label>
            <label><div><strong>Exponential retry backoff</strong><small>{snapshot?.retry_backoff_seconds ?? '—'}s initial · {snapshot?.retry_backoff_max_seconds ?? '—'}s maximum.</small></div><input type="checkbox" checked={Boolean(snapshot?.retry_backoff_seconds)} readOnly /></label>
            <label><div><strong>Durable notification outbox</strong><small>Failures, retry, drain, resource block and cutoff events are retained locally; HTTPS delivery is optional.</small></div><input type="checkbox" checked readOnly /></label>
          </div>
        </div>
      </section>
      <aside className="automation-side">
        <section className="panel safety-card"><p className="panel-kicker">RESOURCE ENVELOPE</p><h3>{preflight?.resources.passed ? 'Admission gates pass' : 'Admission is blocked'}</h3><div className="resource-line"><span>Available memory</span><strong>{preflight ? `${preflight.resources.metrics.available_memory_gib} GiB` : '—'}</strong></div><div className="resource-line"><span>Free project filesystem</span><strong>{preflight ? `${preflight.resources.metrics.free_disk_gib} GiB` : '—'}</strong></div><div className="resource-line"><span>1m load / logical CPU</span><strong>{preflight?.resources.metrics.load_per_cpu ?? '—'}</strong></div><div className="resource-line"><span>Highest thermal-zone reading</span><strong>{preflight?.resources.metrics.temperature_c === null || preflight?.resources.metrics.temperature_c === undefined ? '—' : `${preflight.resources.metrics.temperature_c} °C`}</strong></div><p className="timing-basis-note">These are live claim-time inputs, not utilization estimates. A worker checks the same thresholds before every lease.</p></section>
        <section className="panel preflight-card"><p className="panel-kicker">PREFLIGHT</p><h3>{preflight?.ready ? 'Ready for an admitted claim' : snapshot?.armed ? 'Claim currently gated' : 'Queue deliberately disarmed'}</h3><ul><li className={snapshot ? 'ok' : 'warn'}>{snapshot ? `${snapshot.batches.length} immutable batch plans synchronized` : 'Coordinator ledger not synchronized'}</li><li className={pool && pool.eligible_jobs > 0 && pool.blocked === 0 ? 'ok' : 'warn'}>{pool?.eligible_jobs ?? '—'} typed library-local jobs detected · {pool?.blocked ?? '—'} blocked</li><li className={factory.capabilities?.analysis.ready ? 'ok' : 'warn'}>Ghidra / Java / PyGhidra {factory.capabilities?.analysis.ready ? 'configured' : 'needs worker environment configuration'}</li><li className={preflight?.schedule.claims_allowed ? 'ok' : 'warn'}>Schedule: {preflight?.schedule.reason ?? 'not evaluated'}{preflight?.schedule.next_window_at ? ` · next ${new Date(preflight.schedule.next_window_at).toLocaleString()}` : ''}</li><li className={preflight?.resources.passed ? 'ok' : 'warn'}>Resource gates: {preflight?.resources.passed ? 'pass' : preflight?.resources.reasons.join(', ') || 'not evaluated'}</li></ul><button onClick={() => void factory.refresh()} disabled={factory.connection === 'connecting'}>Run read-only preflight</button></section>
      </aside>
    </div>
  </div>;
}

function ActivityView({ events, connection }: { events: CoordinatorEvent[]; connection: string }) {
  const displayed = [...events].reverse();
  return <div className="view-stack"><ViewIntro kicker="DURABLE TELEMETRY" title="Activity stream" copy="Append-only coordinator events from the local SQLite ledger. Queue, stage and authenticated worker-registration transitions remain auditable here." action={<button className="secondary-action" disabled>{connection === 'live' ? `${events.length} events` : 'Coordinator offline'}</button>} />
    <section className="panel terminal-panel"><div className="terminal-toolbar"><div><span /><span /><span /></div><code>var/fidb-coordinator/ledger.sqlite3 / events</code><button disabled>{connection === 'live' ? 'Live poll' : 'Not live'}</button></div><div className="terminal-events">{displayed.map(event => <div key={event.event_id}><time>{eventTime(event, true)}</time><span className={`event-dot ${eventTone(event)}`} /><strong>{event.event_type}</strong><p>{eventDetail(event)}</p></div>)}{!displayed.length && <div className="empty-state"><time>—</time><span className="event-dot info"/><strong>No events</strong><p>Synchronize the queue to begin the ledger.</p></div>}</div></section>
  </div>;
}
