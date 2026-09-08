'use client';

import { Fragment, useEffect, useState, useSyncExternalStore, type CSSProperties } from 'react';
import {
  useFactoryApi,
  type CoordinatorAttempt,
  type CoordinatorBatch,
  type CoordinatorEvent,
  type CoordinatorJob,
  type CoordinatorSnapshot,
  type CoordinatorWorker,
  type StageSpan,
  type TimingEta,
  type PlanDraftResult,
  type PerformanceProfiles,
  type CoverageLanguage,
  type FactoryCapabilities,
  type ToolchainProfilePlan,
  type WidthAxisId,
  type WidthBatch,
  type WidthCompilation,
  type WidthStudy,
  type CampaignProgramme,
  type CohortValidationLifecycle,
  type CohortValidationProgramme,
} from './use-factory-api';
import { formatBytes } from './formatters';
import { PanelReadWarning, ViewIntro, type FactoryApiState } from './panel-primitives';
import {
  EcologicalValidationView,
  HashDiscriminationView,
  MachineValidationView,
} from './validation-views';

const navItems = [
  ['01', 'Overview'],
  ['02', 'Matrix'],
  ['03', 'Batches'],
  ['04', 'Targets & toolchains'],
  ['05', 'Evidence'],
];

const validationNavItems = [
  ['06', 'Machine validation'],
  ['07', 'Ecological validation'],
  ['08', 'Hash discrimination'],
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

function externalWorkerDisplay(worker: CoordinatorWorker) {
  const raw = worker.metadata.external_toolchain;
  const external = raw && typeof raw === 'object' ? raw as Record<string, unknown> : null;
  const rawMetadata = external?.metadata;
  const metadata = rawMetadata && typeof rawMetadata === 'object'
    ? rawMetadata as Record<string, unknown>
    : null;
  const rawDefinition = external?.definition;
  const definition = rawDefinition && typeof rawDefinition === 'object'
    ? rawDefinition as Record<string, unknown>
    : null;
  const languages = Array.isArray(definition?.languages)
    ? definition.languages.filter(value => typeof value === 'string').join(' + ')
    : null;
  const details = metadata
    ? [metadata.hardware, metadata.macos_version, metadata.xcode_version, metadata.sdk_version]
      .filter(value => typeof value === 'string')
      .join(' · ')
    : `${worker.transport} · ${worker.pools.join(', ')}`;
  return {
    details: `${details}${details ? ' · ' : ''}last seen ${new Date(worker.last_seen_at).toLocaleString()}`,
    state: external?.ready === true && languages ? `${languages} ready` : worker.state,
    tone: worker.state === 'online' && (external === null || external.ready === true) ? 'ready' : 'offline',
  };
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

function formatPlanningDurationNs(value: number | null | undefined) {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return '—';
  const days = value / 86_400_000_000_000;
  if (days < 1) return formatDurationNs(value);
  if (days < 365) return `${days < 10 ? days.toFixed(1) : Math.round(days)} d`;
  const years = days / 365.25;
  return `${years < 10 ? years.toFixed(1) : Math.round(years)} y`;
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

function lifecycleTone(state: string) {
  return state === 'qualified' || state === 'prepared' || state === 'bound-verified' || state === 'composed' || state === 'verified-cached' ? 'ready' : state.includes('broken') ? 'warning' : 'cold';
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
  const [selectedLanguageId, setSelectedLanguageId] = useState('c');
  const [batchOrder, setBatchOrder] = useState<string[]>([]);
  const interfaceScale = useSyncExternalStore<InterfaceScale>(subscribeInterfaceScale, readInterfaceScale, () => 1);
  const factory = useFactoryApi();
  const planBatchRows: BatchRow[] = (factory.authority?.plans ?? []).map(plan => {
    const desired = plan.summary.desired_cells ?? 0;
    const built = plan.inventory.summary.built ?? 0;
    const kinds = Array.from(new Set(plan.matrices.map(matrix => String(matrix.kind ?? 'unknown'))));
    const executors = Array.from(new Set(plan.matrices.map(matrix => (
      matrix.kind === 'native' || matrix.kind === 'width-native' ? 'native' : String(matrix.executor ?? 'unspecified')
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
  const widthStudyBatchRows: BatchRow[] = (factory.authority?.width_studies ?? []).map(study => {
    const defaultPreset = study.presets.find(preset => preset.id === study.default_preset);
    const reviewed = study.readiness.reviewed_recipe_families;
    return {
      id: study.id,
      name: study.name,
      status: 'Defined',
      progress: `${reviewed} / ${study.family_count} families recipe-ready`,
      percent: Math.round((reviewed / study.family_count) * 100),
      worker: '—',
      route: defaultPreset
        ? `${defaultPreset.metrics.build_width_per_family}/family · width study`
        : 'width study',
      eta: '—',
      tier: 'W',
      note: `${study.authority_path} · ${defaultPreset?.metrics.build_cells.toLocaleString() ?? '—'} default build cells`,
    };
  });
  const plannedHoursByBatch = new Map<string, number>();
  for (const block of factory.authority?.time_block_plan.blocks ?? []) {
    for (const item of block.items) {
      plannedHoursByBatch.set(
        item.batch_id,
        (plannedHoursByBatch.get(item.batch_id) ?? 0) + item.estimated_hours,
      );
    }
  }
  const widthBatchRows: BatchRow[] = (factory.authority?.width_batches ?? []).map((batch: WidthBatch) => {
    const ready = batch.readiness.recipe_ready_libraries;
    const estimatedHours = plannedHoursByBatch.get(batch.id);
    return {
      id: batch.id,
      name: batch.name,
      status: batch.readiness.blockers.length ? 'Blocked' : 'Defined',
      progress: `${ready} / ${batch.summary.libraries} recipes · qualification ${batch.qualification.state.replaceAll('-', ' ')}`,
      percent: Math.round((ready / batch.summary.libraries) * 100),
      worker: '—',
      route: `${batch.summary.route_profiles} routes × ${batch.summary.executable_treatments} treatments`,
      eta: estimatedHours === undefined ? '—' : `≈${estimatedHours.toFixed(1)}h`,
      tier: 'W+',
      note: `${batch.authority_path} · ${batch.summary.total_executions.toLocaleString()} exact executions · ${batch.qualification.promotion_state.replaceAll('-', ' ')}`,
    };
  });
  const materializedBatchRows: BatchRow[] = (factory.authority?.materialized_campaigns ?? [])
    .flatMap(campaign => campaign.blocks.map((block): BatchRow => ({
      id: block.id,
      name: block.source_ids.join(' + '),
      status: campaign.readiness.ready ? 'Defined' : 'Blocked',
      progress: `0 / ${block.executions.toLocaleString()} cells completed`,
      percent: 0,
      worker: '—',
      route: `${block.executions.toLocaleString()} exact width cells`,
      eta: `≈${block.estimated_hours.toFixed(1)}h`,
      tier: 'W2',
      note: `${block.plan} · ${block.plan_integrity} · queue #${block.queue_position ?? '—'}`,
    })));
  const validationBatchRows: BatchRow[] = (factory.authority?.machine_validations ?? []).map(validation => ({
    id: `validation:${validation.id}`,
    name: validation.label,
    status: validation.readiness.eligible ? 'Defined' : 'Blocked',
    progress: `${validation.summary.complete_libraries} / ${validation.summary.cohort_libraries} libraries complete`,
    percent: Math.round((validation.summary.completed_exact_inputs / validation.summary.required_exact_inputs) * 100),
    worker: 'validation',
    route: `${validation.batch_kind} · ${validation.summary.exact_identities} identities`,
    eta: `≈${validation.planning.central_wall_hours.toFixed(0)}h`,
    tier: 'V',
    note: `${validation.batch.scheduler_registry} · automatic after cohort · first run canary-gated`,
  }));
  const staticWidthRows = [...materializedBatchRows, ...validationBatchRows, ...widthStudyBatchRows, ...widthBatchRows];
  const authorityBatchRows = [...planBatchRows, ...staticWidthRows];
  const currentBatchRows = factory.snapshot
    ? [
      ...resolvedBatchRows(factory.snapshot),
      ...staticWidthRows.filter(row => (
        !factory.snapshot?.batches.some(batch => batch.id === row.id)
      )),
    ]
    : authorityBatchRows;
  const effectiveBatchOrder = factory.snapshot
    ? [
      ...factory.snapshot.batches.map(batch => batch.id),
      ...staticWidthRows.map(row => row.id).filter(id => (
        !factory.snapshot?.batches.some(batch => batch.id === id)
      )),
    ]
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
          <p className="nav-label secondary-label">Validation</p>
          {validationNavItems.map(([number, label]) => (
            <button
              className={activeView === label ? 'nav-item active' : 'nav-item'}
              key={label}
              onClick={() => setActiveView(label)}
            >
              <span>{number}</span>
              {label}
              <em>UC</em>
            </button>
          ))}
          <p className="nav-label secondary-label">Operations</p>
          <button className={activeView === 'Timing' ? 'nav-item operations-nav-item active' : 'nav-item operations-nav-item'} onClick={() => setActiveView('Timing')}>
            <span>09</span>
            Timing
          </button>
          <button className={activeView === 'Performance' ? 'nav-item operations-nav-item active' : 'nav-item operations-nav-item'} onClick={() => setActiveView('Performance')}>
            <span>10</span>
            Performance
          </button>
          <button className={activeView === 'Retention' ? 'nav-item operations-nav-item active' : 'nav-item operations-nav-item'} onClick={() => setActiveView('Retention')}>
            <span>11</span>
            Retention
            {factory.retention?.latest_plan && <em>{factory.retention.latest_plan.summary.actions}</em>}
          </button>
          <button className={activeView === 'Automation' ? 'nav-item operations-nav-item active' : 'nav-item operations-nav-item'} onClick={() => setActiveView('Automation')}>
            <span>12</span>
            Automation
          </button>
          <button className={activeView === 'Activity' ? 'nav-item operations-nav-item active' : 'nav-item operations-nav-item'} onClick={() => setActiveView('Activity')}>
            <span>13</span>
            Activity
          </button>
          <button className={activeView === 'Export' ? 'nav-item operations-nav-item active' : 'nav-item operations-nav-item'} onClick={() => setActiveView('Export')}>
            <span>14</span>
            Export
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
              <p><i className={factory.snapshot?.active_workers ? 'healthy' : 'warning'}>●</i> {factory.snapshot?.performance_profile?.id ?? 'unbound queue policy'}</p>
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
                {(factory.snapshot?.workers ?? []).map(worker => {
                  const display = externalWorkerDisplay(worker);
                  return <div className="worker-row" key={worker.worker_id}><span className={`worker-glyph ${display.tone}`}>⌬</span><div><strong>{worker.worker_id}</strong><small>{display.details}</small></div><span className={`worker-state ${display.tone}`}>{display.state}</span></div>;
                })}
              </div>
              <button className="full-width-button" onClick={() => setActiveView('Targets & toolchains')}>Inspect targets</button>
            </article>

            <article className="panel requirement-panel">
              <div className="alert-icon">!</div>
              <div className="alert-copy">
                <p className="panel-kicker">ACTION REQUIRED</p>
                <h3>{factory.connection === 'live' ? (factory.capabilities?.analysis.ready ? 'Library pool is visible' : 'Worker environment needs configuration') : 'Coordinator API unavailable'}</h3>
                <p>{factory.connection === 'live' ? `${pool?.ready_now ?? 0} jobs are ready immediately; ${pool?.runnable_with_pinned_acquisition ?? 0} can run after pinned acquisition. ${factory.capabilities?.analysis.ghidra.state === 'installed-unconfigured' ? 'Ghidra is installed but GHIDRA_HEADLESS is not configured for the API/worker service.' : ''}` : (factory.error ?? 'Start the loopback API service to read the durable ledger and toolchain inventory.')}</p>
                <div className="alert-tags"><span>library-local</span><span>max {factory.snapshot?.max_workers ?? 2}</span><span>{factory.snapshot?.performance_profile?.id ?? 'profile unbound'}</span><span>no QEMU</span></div>
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
          </> : <SecondaryView view={activeView} navigateTo={setActiveView} batchOrder={effectiveBatchOrder} setBatchOrder={setBatchOrder} rows={currentBatchRows} factory={factory} selectedLanguageId={selectedLanguageId} setSelectedLanguageId={setSelectedLanguageId} />}
        </div>
      </section>
    </main>
  );
}

function SecondaryView({ view, navigateTo, batchOrder, setBatchOrder, rows, factory, selectedLanguageId, setSelectedLanguageId }: { view: string; navigateTo: (view: string) => void; batchOrder: string[]; setBatchOrder: React.Dispatch<React.SetStateAction<string[]>>; rows: BatchRow[]; factory: FactoryApiState; selectedLanguageId: string; setSelectedLanguageId: React.Dispatch<React.SetStateAction<string>> }) {
  if (view === 'Matrix') return <PlannerView batchOrder={batchOrder} rows={rows} factory={factory} selectedLanguageId={selectedLanguageId} setSelectedLanguageId={setSelectedLanguageId} />;
  if (view === 'Machine validation') return <MachineValidationView factory={factory} navigateTo={navigateTo} />;
  if (view === 'Ecological validation') return <EcologicalValidationView factory={factory} />;
  if (view === 'Hash discrimination') return <HashDiscriminationView factory={factory} />;
  if (view === 'Performance') return <PerformanceView factory={factory} />;
  if (view === 'Retention') return <RetentionView factory={factory} />;
  if (view === 'Timing') return <TimingView factory={factory} />;
  if (view === 'Export') return <ExportView factory={factory} />;
  if (view === 'Batches') return <BatchesView onNewBatch={() => navigateTo('Matrix')} batchOrder={batchOrder} setBatchOrder={setBatchOrder} rows={rows} live={Boolean(factory.snapshot)} factory={factory} />;
  if (view === 'Targets & toolchains') return <ToolchainsView factory={factory} selectedLanguageId={selectedLanguageId} setSelectedLanguageId={setSelectedLanguageId} />;
  if (view === 'Evidence') return <EvidenceView snapshot={factory.snapshot} />;
  if (view === 'Automation') return <AutomationView factory={factory} />;
  return <ActivityView events={factory.events} connection={factory.connection} />;
}

function LanguageScopeSelector({ languages, selectedId, onSelect }: { languages: CoverageLanguage[]; selectedId: string; onSelect: (id: string) => void }) {
  const activeLanguages = languages.filter(language => language.state === 'active-scope');
  return <section className="language-scope-selector" aria-label="Active library language scope"><div><span>ACTIVE LIBRARY MATRIX</span><strong>C-family scope · C++ only where a C library requires it</strong></div><div>{activeLanguages.map(language => <button key={language.id} className={selectedId === language.id ? 'active' : ''} onClick={() => onSelect(language.id)} aria-pressed={selectedId === language.id}><b>{language.label}</b><small>{language.state.replaceAll('-', ' ')}</small></button>)}</div></section>;
}

function WidthStudyPanel({ study, compilation, capabilities }: { study: WidthStudy; compilation?: WidthCompilation; capabilities: FactoryCapabilities | null }) {
  const defaultPreset = study.presets.find(preset => preset.id === study.default_preset) ?? study.presets[0];
  const [axisValues, setAxisValues] = useState<Record<WidthAxisId, number>>(() => Object.fromEntries(
    study.axes.map(axis => [axis.id, defaultPreset?.[axis.id] ?? axis.default]),
  ) as Record<WidthAxisId, number>);
  const [targetFamilies, setTargetFamilies] = useState(study.scaling.default_target_families);
  const [workers, setWorkers] = useState(study.scaling.default_workers);
  const [complexityMultiplier, setComplexityMultiplier] = useState(1);
  const [retainedMultiplier, setRetainedMultiplier] = useState(1);
  const buildWidth = axisValues.releases * axisValues.routes * axisValues.build_profiles * axisValues.artifact_shapes;
  const activePreset = study.presets.find(preset => study.axes.every(axis => preset[axis.id] === axisValues[axis.id]));
  const activeRequirements = study.toolchain_requirements.slice(0, axisValues.routes);
  const capabilityById = new Map((capabilities?.toolchains.entries ?? []).map(row => [row.id, row]));
  const requirementState = (requirement: WidthStudy['toolchain_requirements'][number]) => {
    if (requirement.route_state === 'pinned-source' && requirement.source_capable_toolchain_ids.some(id => capabilityById.get(id)?.state === 'verified-cached')) return 'pinned-cache-ready';
    return requirement.route_state;
  };
  const stateLabel: Record<string, string> = {
    installed: 'HOST INSTALLED',
    'pinned-cache-ready': 'PINNED CACHE READY',
    'pinned-source': 'PINNED SOURCE',
    'archive-only': 'ARCHIVE EVIDENCE ONLY',
    'remote-required': 'REMOTE WORKER REQUIRED',
    'definition-required': 'DEFINITION + PIN REQUIRED',
  };
  const nextGate: Record<string, string> = {
    installed: 'Verified',
    'pinned-cache-ready': 'Qualify route',
    'pinned-source': 'Fetch + qualify',
    'archive-only': 'Add compiler pin',
    'remote-required': 'Enroll worker',
    'definition-required': 'Define + pin',
  };
  const stateCounts = activeRequirements.reduce<Record<string, number>>((counts, requirement) => {
    const state = requirementState(requirement);
    counts[state] = (counts[state] ?? 0) + 1;
    return counts;
  }, {});
  const projectionFor = (families: number) => {
    const buildCells = families * buildWidth;
    const analyses = buildCells * axisValues.analysis_profiles;
    const executions = analyses * axisValues.replay;
    const retainedBytes = executions * study.calibration.retained_bundle_bytes_p50 * retainedMultiplier;
    const compactBytes = analyses * study.calibration.compact_output_bytes_p50 * retainedMultiplier;
    return {
      families,
      buildCells,
      analyses,
      executions,
      policyEvaluations: analyses * axisValues.admission_profiles,
      idealWallNs: executions * study.calibration.successful_wall_ns_p50 * complexityMultiplier / workers,
      retainedBytes,
      compactBytes,
      diskBytes: retainedBytes + compactBytes,
    };
  };
  const projections = study.scaling.comparison_family_counts.map(projectionFor);
  const baseline = projectionFor(study.family_count);
  const target = projectionFor(targetFamilies);
  const selectPreset = (preset: WidthStudy['presets'][number]) => setAxisValues(Object.fromEntries(
    study.axes.map(axis => [axis.id, preset[axis.id]]),
  ) as Record<WidthAxisId, number>);
  const updateAxis = (axis: WidthAxisId, value: number) => setAxisValues(current => ({ ...current, [axis]: value }));
  const applicability = new Map(compilation?.applicability.map(row => [`${row.route_id}:${row.profile_id}`, row]));
  return <section className="panel width-study-panel">
    <div className="panel-header width-study-header"><h3>Width laboratory · {study.id}</h3><div><span className="plan-state">DEFINED · DISARMED</span><code>{study.authority_path}</code></div></div>
    <div className="width-study-warning"><span>!</span><p><strong>This is coverage intent, not queued work.</strong><small>{study.queue_policy}</small></p></div>
    {compilation && <section className="compiled-width">
      <header><h4>Applicability · {compilation.id} · {compilation.fixed_recipe}</h4><code>{compilation.compilation_digest.slice(0, 16)}…</code></header>
      {compilation.freeze && <div className="compiled-width-freeze"><span>✓</span><p><strong>FROZEN MEASURED WIDTH · {compilation.freeze.completed_executions} EXECUTIONS COMPLETE</strong><small>{formatPlanningDurationNs(compilation.freeze.wall_time_ns)} wall · {formatBytes(compilation.freeze.peak_active_replay_scratch_bytes)} peak scratch · {formatBytes(compilation.freeze.retained_bytes)} retained · {compilation.freeze.artifact_byte_identical_cells}/54 artifact-byte repeatable · {compilation.freeze.fid_semantic_identical_cells}/54 FID-semantic repeatable</small></p><code>{compilation.freeze.evidence_path}</code></div>}
      <div className="compiled-width-metrics"><article><span>DECLARED ROUTES</span><strong>{compilation.summary.declared_route_slots}</strong><small>{compilation.summary.qualified_routes} qualified now</small></article><article><span>PROFILE SLOTS</span><strong>{compilation.summary.declared_build_profile_slots}</strong><small>{compilation.summary.catalogued_build_profiles} named</small></article><article><span>FEASIBLE BUILD CELLS</span><strong>{compilation.summary.feasible_build_cells}</strong><small>{compilation.summary.executable_route_profile_pairs} applicable pairs</small></article><article><span>REPLAYED FULL PATHS</span><strong>{compilation.summary.feasible_full_path_executions}</strong><small>×{compilation.summary.selected_replay} independent attempts</small></article><article><span>VARIABLES VISIBLE</span><strong>{compilation.summary.sensitivity_factors}</strong><small>{compilation.summary.factors_with_variants} have named choices</small></article></div>
      <details className="applicability-map" open><summary>Target × exact compiler × treatment applicability <span>{compilation.routes.length} routes · {new Set(compilation.routes.map(route => route.compiler_id)).size} compiler identities · {compilation.summary.executable_route_profile_pairs} executable</span></summary><div className="applicability-scroll"><div className="applicability-grid" style={{ '--width-cols': compilation.build_profiles.length } as CSSProperties}><div className="corner">TARGET / COMPILER</div>{compilation.build_profiles.map(profile => <div className="profile-head" key={profile.id} title={profile.controls.join(' · ')}><b>{profile.label}</b><small>{profile.execution_treatment ?? 'not wired'}</small></div>)}{compilation.routes.map(route => <Fragment key={route.id}><div className="route-head"><b>{route.label}</b><small>{route.target_id} · {route.compiler_id}</small></div>{compilation.build_profiles.map(profile => { const cell = applicability.get(`${route.id}:${profile.id}`); return <div key={`${route.id}:${profile.id}`} className={`applicability-cell ${cell?.state ?? 'unavailable'}`} title={cell?.reasons.join(' · ') || cell?.treatment_id || 'Executable'}>{cell?.state === 'executable' ? '●' : cell?.state === 'inapplicable' ? '—' : '!'}</div>; })}</Fragment>)}</div></div></details>
      <div className="compiled-layer-grid"><section><span>ARTIFACT SHAPES · {compilation.artifact_profiles.length}</span>{compilation.artifact_profiles.map(row => <article key={row.id}><b>{row.label}</b><em className={row.state}>{row.state}</em><small>{row.description}</small></article>)}</section><section><span>ANALYSIS PROFILES · {compilation.analysis_profiles.length}</span>{compilation.analysis_profiles.map(row => <article key={row.id}><b>{row.label}</b><em className={row.state}>{row.state}</em><small>{row.description}</small></article>)}</section><section><span>ADMISSION PROFILES · {compilation.admission_profiles.length}</span>{compilation.admission_profiles.map(row => <article key={row.id}><b>{row.label}</b><em className={row.state}>{row.state}</em><small>{row.description}</small></article>)}</section></div>
      <details className="compiled-factor-ledger"><summary>All {compilation.factors.length} studied variables <span>registered, desired, guarded and unresolved choices remain visible</span></summary><div>{compilation.factors.map((factor, index) => <article key={factor.id}><b>{String(index + 1).padStart(2, '0')}</b><p><strong>{factor.label}</strong><small>{factor.id} · {factor.stage}</small></p><span>{factor.variants.length ? factor.variants.map(row => `${row.label} [${row.state}]`).join(' · ') : 'No named variants yet · explicit unresolved width'}</span></article>)}</div></details>
    </section>}
    <div className="width-study-presets"><span>WIDTH PRESET</span><div>{study.presets.map(preset => <button key={preset.id} className={activePreset?.id === preset.id ? 'active' : ''} onClick={() => selectPreset(preset)} title={preset.description}><b>{preset.label}</b><small>{preset.metrics.build_width_per_family.toLocaleString()} builds/family · {preset.evidence_class}</small></button>)}</div><em>{activePreset ? activePreset.description : 'Custom width · bounded by the declared study authority'}</em></div>
    <div className="width-axis-grid">{study.axes.map(axis => <label key={axis.id}><span><b>{axis.label}</b><strong>{axisValues[axis.id]}</strong></span><input type="range" min={axis.minimum} max={axis.maximum} value={axisValues[axis.id]} onChange={event => updateAxis(axis.id, Number(event.target.value))} /><small>{axis.minimum}–{axis.maximum} {axis.unit} · {axis.layer}</small><p>{axis.description}</p></label>)}</div>
    <div className="width-study-metrics">
      <article><span>BUILD WIDTH / FAMILY</span><strong>{buildWidth.toLocaleString()}</strong><small>releases × routes × build profiles × shapes</small></article>
      <article><span>TOP-10 BUILD CELLS</span><strong>{baseline.buildCells.toLocaleString()}</strong><small>distinct compiled/artifact identities</small></article>
      <article><span>ANALYSIS RUNS</span><strong>{baseline.analyses.toLocaleString()}</strong><small>reuse build artifacts · ×{axisValues.analysis_profiles}</small></article>
      <article><span>FULL-PATH EXECUTIONS</span><strong>{baseline.executions.toLocaleString()}</strong><small>analysis runs × {axisValues.replay} replay</small></article>
      <article><span>POLICY EVALUATIONS</span><strong>{baseline.policyEvaluations.toLocaleString()}</strong><small>reuse evidence · ×{axisValues.admission_profiles}</small></article>
    </div>
    <div className="width-study-body">
      <section className="width-family-card"><header><h4>Subject set · top 10 C</h4><span>{study.readiness.reviewed_recipe_families}/{study.family_count} recipe-ready</span></header><div>{study.families.map(family => <article key={family.id}><b>{String(family.rank).padStart(2, '0')}</b><p><strong>{family.label}</strong><small>{family.selection_evidence}</small></p><em className={family.recipe_state}>{family.recipe_state.replaceAll('-', ' ')}</em></article>)}</div><footer>{study.caveat}</footer></section>
      <section className="width-scale-card"><header><h4>10 → 80 capacity</h4><span>n={study.calibration.sample_count} smoke samples</span></header>
        <div className="width-scale-controls"><label><span>FAMILIES</span><div>{study.scaling.comparison_family_counts.map(count => <button key={count} className={targetFamilies === count ? 'active' : ''} onClick={() => setTargetFamilies(count)}>{count}</button>)}</div></label><label><span>WORKER SLOTS <b>{workers}</b></span><input type="range" min="1" max={study.scaling.maximum_workers} value={workers} onChange={event => setWorkers(Number(event.target.value))} /></label><label><span>TIME COMPLEXITY × <b>{complexityMultiplier}</b></span><input type="range" min="1" max="50" value={complexityMultiplier} onChange={event => setComplexityMultiplier(Number(event.target.value))} /></label><label><span>RETAINED BYTES × <b>{retainedMultiplier}</b></span><input type="range" min="1" max="20" value={retainedMultiplier} onChange={event => setRetainedMultiplier(Number(event.target.value))} /></label></div>
        <div className="width-delta"><span>10 → {targetFamilies} DELTA</span><div><p><strong>+{(target.executions - baseline.executions).toLocaleString()}</strong><small>full-path executions</small></p><p><strong>+{formatPlanningDurationNs(target.idealWallNs - baseline.idealWallNs)}</strong><small>ideal occupied-slot wall time</small></p><p><strong>+{formatBytes(target.diskBytes - baseline.diskBytes)}</strong><small>retained + compact disk proxy</small></p><p><strong>{formatBytes(workers * study.calibration.peak_worker_rss_bytes_p50)}</strong><small>concurrent RSS proxy</small></p></div></div>
        <div className="width-scale-table"><div className="head"><span>Families</span><span>Build cells</span><span>Executions</span><span>Ideal wall</span><span>Retained</span><span>Compact</span></div>{projections.map(row => <div className={row.families === targetFamilies ? 'selected' : ''} key={row.families}><strong>{row.families}</strong><span>{row.buildCells.toLocaleString()}</span><span>{row.executions.toLocaleString()}</span><b>{formatPlanningDurationNs(row.idealWallNs)}</b><span>{formatBytes(row.retainedBytes)}</span><span>{formatBytes(row.compactBytes)}</span></div>)}</div>
        <footer><strong>Smoke-linear projection; not an ETA.</strong> {study.calibration.caveat} Scratch peak: {study.calibration.scratch_peak_state}. Model: {study.scaling.model}.</footer>
      </section>
    </div>
    <section className="width-toolchain-card"><header><h4>Route acquisition · {axisValues.routes}/{study.toolchain_requirements.length} active</h4><div className="width-route-counts"><span className="installed">{(stateCounts.installed ?? 0) + (stateCounts['pinned-cache-ready'] ?? 0)} ready</span><span className="remote-required">{stateCounts['remote-required'] ?? 0} remote</span><span className="definition-required">{(stateCounts['definition-required'] ?? 0) + (stateCounts['archive-only'] ?? 0)} definitions</span></div></header><div className="width-toolchain-list">{study.toolchain_requirements.map(requirement => {
      const active = requirement.order <= axisValues.routes;
      const state = requirementState(requirement);
      return <article className={active ? `active ${state}` : 'future'} key={requirement.id}><b>{String(requirement.order).padStart(2, '0')}</b><div><strong>{requirement.target_label}</strong><small>{requirement.target_id} · {requirement.wave}</small></div><p><strong>{requirement.compiler_label}</strong><small>{requirement.worker_class} · {requirement.acquisition}</small></p><span className={`route-requirement-state ${state}`}>{active ? stateLabel[state] : 'OUTSIDE CURRENT WIDTH'}</span><code>{requirement.version_policy}</code><button disabled title="Install actions require an exact reviewed pin and remain intentionally disabled in this coverage-intent batch">{active ? nextGate[state] : 'Later wave'}</button></article>;
    })}</div></section>
    {study.readiness.blockers.length > 0 && <details className="width-blockers"><summary>Materialization blockers <span>{study.readiness.blockers.length}</span></summary><div>{study.readiness.blockers.map(blocker => <p key={blocker}>! {blocker}</p>)}</div></details>}
  </section>;
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

function PlannerView({ batchOrder, rows, factory, selectedLanguageId, setSelectedLanguageId }: { batchOrder: string[]; rows: BatchRow[]; factory: FactoryApiState; selectedLanguageId: string; setSelectedLanguageId: React.Dispatch<React.SetStateAction<string>> }) {
  const executor = 'local';
  const timing = factory.timings;
  const [selectedRecipesOverride, setSelectedRecipesOverride] = useState<string[] | null>(null);
  const [routeSelectionsOverride, setRouteSelectionsOverride] = useState<Record<string, string[]> | null>(null);
  const [factorSelectionsOverride, setFactorSelectionsOverride] = useState<Record<string, string[]> | null>(null);
  const [collapsedVariableGroups, setCollapsedVariableGroups] = useState(['executable-routes', 'analysis-controls', 'environment-identity', 'fid-matching', 'truth-admission', 'hardening-instrumentation', 'link-output', 'analysis-recovery']);
  const [collapsedLibraryGroups, setCollapsedLibraryGroups] = useState<string[]>([]);
  const [matrixLayer, setMatrixLayer] = useState<'both' | 'plan' | 'inventory'>('both');
  const [queueStrategyOverride, setQueueStrategyOverride] = useState<string | null>(null);
  const [queueMessage, setQueueMessage] = useState('');
  const [inspectedRecipe, setInspectedRecipe] = useState<string | null>(null);
  const [inspectedFactor, setInspectedFactor] = useState<string | null>(null);
  const [tomlOpen, setTomlOpen] = useState(true);
  const [scopeOpen, setScopeOpen] = useState(false);
  const [widthLaboratoryOpen, setWidthLaboratoryOpen] = useState(false);
  const [crosspointOpen, setCrosspointOpen] = useState(false);
  const [draftName, setDraftName] = useState('matrix-draft');
  const [draftResult, setDraftResult] = useState<PlanDraftResult | null>(null);
  const [validatedToml, setValidatedToml] = useState<string | null>(null);
  const [savedDraftSha256, setSavedDraftSha256] = useState<string | null>(null);
  const [draftMessage, setDraftMessage] = useState('Resolve the generated request before saving it.');
  const authority = factory.authority;
  const coverageUniverse = authority?.coverage_universe;
  const widthStudy = authority?.width_studies.find(study => study.language_id === selectedLanguageId);
  const widthCompilation = authority?.width_compilations
    .filter(compilation => compilation.language_id === selectedLanguageId)
    .sort((left, right) => (
      right.summary.feasible_full_path_executions
      - left.summary.feasible_full_path_executions
    ))[0];
  const machineValidation = selectedLanguageId === 'c'
    ? factory.machineValidation
    : authority?.machine_validations.find(validation => validation.language_id === selectedLanguageId);
  const ecologicalValidation = factory.ecologicalValidation;
  const noisyHashes = factory.noisyHashes;
  const hashDiscrimination = authority?.hash_discrimination;
  const retention = factory.retention;
  const qualificationPipeline = authority?.qualification_pipeline;
  const selectedLanguage = coverageUniverse?.languages.find(language => language.id === selectedLanguageId);
  const languageProfiles = (coverageUniverse?.profiles ?? []).filter(profile => profile.language_id === selectedLanguageId);
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
  const catalogFactorGroups = selectedLanguageId === 'c'
    ? factorStageIds.map(stage => ({
      id: 'known-' + stage,
      label: humanize(stage),
      note: 'known C sensitivity and provenance dimensions',
      options: (authority?.factors ?? [])
        .filter(factor => factor.stage === stage)
        .map(factor => ({
          id: factor.id,
          label: factor.label,
          detail: factor.impact,
          state: factor.confidence === 'observed-sensitive' ? 'recorded' : 'known',
        })),
    }))
    : selectedLanguage
      ? [{
        id: `${selectedLanguage.id}-treatments`,
        label: `${selectedLanguage.label} treatment policy`,
        note: 'language-owned axes; finite profiles still require qualification',
        options: selectedLanguage.treatment_axes.map((axis, index) => ({
          id: `${selectedLanguage.id}:axis:${index + 1}`,
          label: axis,
          detail: selectedLanguage.denominator,
          state: selectedLanguage.state === 'vocabulary-only' ? 'conceptual' : 'known',
        })),
      }]
      : [];
  const scopedFactorGroups = selectedLanguageId === 'c' ? factorGroups : [];
  const allFactorOptions = scopedFactorGroups.flatMap(group => group.options);
  const knownFactorCount = authority?.factors.length ?? 0;
  const measuredFactorCount = authority?.factors.filter(factor => (
    factor.confidence.startsWith('observed')
  )).length ?? 0;
  const variantCountsByFactor = (authority?.factor_variants ?? []).reduce<Record<string, number>>((counts, variant) => ({
    ...counts,
    [variant.factor]: (counts[variant.factor] ?? 0) + 1,
  }), {});
  const rawNamedTreatmentSpace = selectedLanguageId === 'c' ? Object.values(variantCountsByFactor).reduce(
    (product, count) => product * count,
    Object.keys(variantCountsByFactor).length ? 1 : 0,
  ) : 0;
  const executableTargetCount = (authority?.targets ?? []).filter(target => (
    target.native_route_ids.length > 0 || target.source_capable_toolchain_ids.length > 0
  )).length;
  const targetContextOptions = (authority?.targets ?? []).map(target => {
    const executable = target.native_route_ids.length > 0 || target.source_capable_toolchain_ids.length > 0;
    const state = executable
      ? 'executable'
      : target.catalog_state === 'coverage-intent'
        ? 'conceptual'
        : target.catalog_state === 'study-observed'
          ? 'observed'
          : 'catalogued';
    return {
      id: `target:${target.id}`,
      label: target.label,
      detail: `${target.bits}-bit · ${target.endianness} · ${target.binary_format}`,
      state,
      compatible: ['native', 'source', 'malware'],
      kind: 'target',
    };
  });
  const compilerProfileOptions = languageProfiles.map(profile => ({
    id: `profile:${profile.id}`,
    label: profile.label,
    detail: `${profile.route_scope} · ${profile.controls.join(' · ')}`,
    state: profile.state,
    compatible: ['native', 'source', 'malware'],
    kind: 'profile',
  }));
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
    { id: 'target-contexts', label: 'Target / ISA / ABI', note: 'catalogued possibility space; readiness is an overlay', options: targetContextOptions },
    { id: 'executable-routes', label: 'Executable route identities', note: 'registered native and pinned source/archive routes', options: routeColumns },
    { id: 'compiler-profiles', label: 'Compiler calibration profiles', note: 'bounded family × version × setting pack', options: compilerProfileOptions },
    ...catalogFactorGroups.map(group => ({ ...group, options: group.options.map(option => ({ ...option, kind: 'catalog', compatible: ['native', 'source', 'malware'] })) })),
    ...scopedFactorGroups.map(group => ({ ...group, options: group.options.map(option => ({ ...option, kind: 'factor', compatible: ['native'] })) })),
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
  const scopedRecipeOptions = selectedLanguageId === 'c' ? recipeOptions : [];
  const orderedRecipeOptions = [...scopedRecipeOptions].sort((left, right) => batchRank(left.batch) - batchRank(right.batch));
  const selectedRecipeRows = orderedRecipeOptions.filter(recipe => recipe.planEligible && selectedRecipes.includes(recipe.id));
  const inspected = scopedRecipeOptions.find(recipe => recipe.id === inspectedRecipe);
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
  const completedCellIds = new Set([
    ...builtCellIds,
    ...(factory.snapshot?.jobs ?? [])
      .filter(job => job.state === 'complete')
      .map(job => job.base_cell),
  ]);
  const cellRoute = (cellId: string) => cellId.split(':').at(-2) ?? 'unknown-route';
  const cellTreatment = (cellId: string) => cellId.split(':').at(-1) ?? 'unknown-treatment';
  const frozenWidthByRecipe = new Map<string, WidthCompilation[]>();
  for (const compilation of authority?.width_compilations ?? []) {
    if (!compilation.freeze) continue;
    const recipeName = compilation.fixed_recipe.split('@', 1)[0];
    frozenWidthByRecipe.set(recipeName, [
      ...(frozenWidthByRecipe.get(recipeName) ?? []),
      compilation,
    ]);
  }
  const builtWidthRows = recipeOptions.map(recipe => {
    const cellIds = [...completedCellIds].filter(cellId => (
      cellMatchesRecipe(cellId, recipe.name, recipe.version)
    ));
    const frozen = frozenWidthByRecipe.get(recipe.name) ?? [];
    const measuredRuns = (factory.laneInventory?.width_runs ?? [])
      .filter(run => (
        run.state === 'measured-complete'
        && run.fixed_recipe?.split('@', 1)[0] === recipe.name
      ))
      .sort((left, right) => right.completed_executions - left.completed_executions);
    const widestMeasuredRun = measuredRuns[0];
    const measuredCompilation = authority?.width_compilations.find(compilation => (
      compilation.id === widestMeasuredRun?.width_id
    ));
    const measuredTreatmentCount = new Set(
      (measuredCompilation?.build_profiles ?? [])
        .map(profile => profile.execution_treatment)
        .filter((value): value is string => Boolean(value)),
    ).size;
    const measuredPairCount = widestMeasuredRun?.successful_route_profile_pairs ?? 0;
    const measuredRouteCount = measuredTreatmentCount > 0
      && measuredPairCount % measuredTreatmentCount === 0
      ? measuredPairCount / measuredTreatmentCount
      : 0;
    const frozenCells = frozen.reduce((total, compilation) => (
      total + (compilation.freeze?.completed_executions ?? 0)
    ), 0);
    const frozenRoutes = new Set(frozen.flatMap(compilation => (
      compilation.routes.map(route => route.id)
    )));
    const frozenTreatments = new Set(frozen.flatMap(compilation => (
      compilation.build_profiles
        .map(profile => profile.execution_treatment)
        .filter((value): value is string => Boolean(value))
    )));
    return {
      recipe,
      cells: Math.max(cellIds.length, frozenCells, measuredPairCount),
      routes: Math.max(new Set(cellIds.map(cellRoute)).size, frozenRoutes.size, measuredRouteCount),
      treatments: Math.max(
        new Set(cellIds.map(cellTreatment)).size,
        frozenTreatments.size,
        measuredTreatmentCount,
      ),
      sources: [
        cellIds.length ? 'ledger / sealed inventory' : null,
        frozen.length ? `${frozen.length} frozen width run${frozen.length === 1 ? '' : 's'}` : null,
        widestMeasuredRun
          ? `${widestMeasuredRun.completed_executions} measured executions · ${measuredPairCount} unique route/profile pairs`
          : null,
      ].filter((value): value is string => Boolean(value)),
    };
  }).filter(row => row.cells > 0)
    .sort((left, right) => right.cells - left.cells || left.recipe.name.localeCompare(right.recipe.name));
  const scheduledBatchRows = batchOrder.filter(batchId => (
    factory.snapshot?.batches.some(batch => batch.id === batchId)
  )).map((batchId, index) => {
    const batch = factory.snapshot?.batches.find(row => row.id === batchId);
    const batchJobs = (factory.snapshot?.jobs ?? []).filter(job => job.batch_id === batchId);
    const recipeNamesFromJobs = recipeOptions
      .filter(recipe => batchJobs.some(job => cellMatchesRecipe(job.base_cell, recipe.name, recipe.version)))
      .map(recipe => recipe.name);
    const recipeNames = recipeNamesFromJobs.length
      ? recipeNamesFromJobs
      : recipeOptions.filter(recipe => recipe.batch === batchId).map(recipe => recipe.name);
    const stateCounts = batchJobs.reduce<Record<string, number>>((counts, job) => ({
      ...counts,
      [job.state]: (counts[job.state] ?? 0) + 1,
    }), {});
    const queued = (stateCounts.queued ?? 0) + (stateCounts.leased ?? 0) + (stateCounts.running ?? 0);
    return {
      id: batchId,
      position: batch?.position ?? index + 1,
      label: batch?.name ?? rows.find(row => row.id === batchId)?.name ?? batchId,
      planPath: batch?.plan_path ?? rows.find(row => row.id === batchId)?.note ?? 'plans/priority-queue.toml',
      recipeNames,
      jobs: batchJobs.length,
      complete: stateCounts.complete ?? 0,
      failed: (stateCounts.failed ?? 0) + (stateCounts.blocked ?? 0),
      queued,
    };
  }).sort((left, right) => left.position - right.position);
  const nextScheduledBatchId = scheduledBatchRows.find(row => row.queued > 0)?.id ?? null;
  const unscheduledRecipes = recipeOptions.filter(recipe => (
    recipe.planEligible && recipe.batch === 'unassigned'
  ));
  const missingRecipeFamilies = (widthStudy?.families ?? []).filter(family => (
    family.recipe_state !== 'reviewed-recipe' || family.recipe_ids.length === 0
  ));
  const missingToolchainRequirements = (widthStudy?.toolchain_requirements ?? []).filter(requirement => (
    requirement.native_route_ids.length === 0
    && requirement.source_capable_toolchain_ids.length === 0
  ));
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
  const malwareRecipe = scopedRecipeOptions.find(recipe => recipe.mode === 'malware');
  const malwareInventory = malwareRecipe ? inventoryCells.filter(([cellId]) => (
    cellMatchesRecipe(cellId, malwareRecipe.name, malwareRecipe.version)
  )) : [];
  const measuredEtaNs = etaDuration(timing?.eta ?? null);
  const selectedFactorRows = allFactorOptions.filter(option => selectedRecipeRows.some(recipe => (factorSelections[recipe.id] || []).includes(option.id)));
  const toggleRecipe = (id: string) => {
    if (!scopedRecipeOptions.find(recipe => recipe.id === id)?.planEligible) return;
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
      <ViewIntro kicker="ANALYST MATRIX" title={`${selectedLanguage?.label ?? 'C'} coverage matrix`} action={<button className="secondary-action" onClick={() => setTomlOpen(!tomlOpen)} disabled={selectedLanguageId !== 'c'}>{selectedLanguageId === 'c' ? `${tomlOpen ? 'Hide' : 'Show'} TOML` : 'No executable draft'}</button>} />

      <LanguageScopeSelector languages={coverageUniverse?.languages ?? []} selectedId={selectedLanguageId} onSelect={setSelectedLanguageId} />

      {selectedLanguageId === 'c' && authority?.cohort_validation && (
        <CohortValidationLifecyclePanel lifecycle={authority.cohort_validation} />
      )}

      {selectedLanguageId === 'c' && authority?.campaign_programmes.map(programme => (
        <CampaignProgrammePanel
          key={programme.id}
          programme={programme}
          lifecycle={authority.cohort_validation?.programmes.find(row => row.id === programme.id)}
        />
      ))}

      <section className="panel operational-matrix-index" aria-label="Operational matrix build order">
        <header>
          <h3>Operational matrix</h3>
          <div className="operational-matrix-counts"><span><b>{builtWidthRows.length}</b> built subjects</span><span><b>{scheduledBatchRows.length}</b> ordered batches</span><span><b>{qualificationPipeline ? `${qualificationPipeline.summary.satisfied}/${qualificationPipeline.summary.batches}` : '—'}</b> qualification gates</span><span><b>{unscheduledRecipes.length}</b> buildable / unscheduled</span><span><b>{missingRecipeFamilies.length}</b> recipe gaps</span><span><b>{missingToolchainRequirements.length}</b> toolchain gaps</span></div>
        </header>

        <section className="operational-matrix-band built-band">
          <div className="operational-band-title"><b>01</b><span><strong>Already built</strong><small>Sealed evidence, with achieved width—not declared possibility.</small></span><em>{builtWidthRows.reduce((total, row) => total + row.cells, 0).toLocaleString()} cells</em></div>
          <div className="operational-built-list">
            {builtWidthRows.map(row => <article key={row.recipe.id}><span className="operational-state built">BUILT</span><p><strong>{row.recipe.name} {row.recipe.version}</strong><small>{row.sources.join(' · ')}</small></p><dl><div><dt>CELLS</dt><dd>{row.cells}</dd></div><div><dt>ROUTES</dt><dd>{row.routes}</dd></div><div><dt>TREATMENTS</dt><dd>{row.treatments}</dd></div></dl></article>)}
            {!builtWidthRows.length && <div className="operational-empty"><strong>No sealed builds detected</strong><small>Declared routes and loose artifacts are deliberately not counted as built.</small></div>}
          </div>
        </section>

        <section className="operational-matrix-band scheduled-band">
          <div className="operational-band-title"><b>02</b><span><strong>Scheduled next</strong><small>Exact execution order from plans/priority-queue.toml and its synchronized ledger.</small></span><em>{scheduledBatchRows.reduce((total, row) => total + row.jobs, 0).toLocaleString()} cells</em></div>
          <ol className="operational-batch-list">
            {scheduledBatchRows.map(row => {
              const complete = row.jobs > 0 && row.complete === row.jobs;
              const state = complete ? 'complete' : row.id === nextScheduledBatchId ? 'next' : row.failed > 0 && row.queued === 0 ? 'blocked' : 'scheduled';
              return <li className={state} key={row.id}><b>{String(row.position).padStart(2, '0')}</b><span className={`operational-state ${state}`}>{state === 'next' ? 'NEXT' : state.toUpperCase()}</span><p><strong>{row.label}</strong><small>{row.recipeNames.join(' + ') || row.planPath}</small></p><div><span><b>{row.complete}</b> complete</span><span><b>{row.queued}</b> remaining</span>{row.failed > 0 && <span className="failed"><b>{row.failed}</b> failed / blocked</span>}</div></li>;
            })}
            {!scheduledBatchRows.length && <li className="empty"><p><strong>No active queue batches</strong><small>Add reviewed plan paths to the TOML queue; draft selections are not scheduled work.</small></p></li>}
          </ol>
        </section>

        {qualificationPipeline && <section className="operational-matrix-band qualification-band">
          <div className="operational-band-title"><b>03</b><span><strong>Campaign qualification</strong><small>Real compilation-only gate between reviewed recipes and queue-eligible campaign blocks.</small></span><em>{qualificationPipeline.summary.qualified} qualified · {qualificationPipeline.summary.blocked} blocked · enforced</em></div>
          <div className="operational-qualification-list">
            {qualificationPipeline.gates.map(gate => {
              const tone = gate.state === 'qualified' ? 'ready' : gate.state === 'historical-exempt' ? 'complete' : 'blocked';
              const label = gate.state === 'historical-exempt' ? 'HISTORICAL SEAL' : gate.state.replaceAll('-', ' ').toUpperCase();
              return <article key={gate.batch_id}><span className={`operational-state ${tone}`}>{label}</span><p><strong>{gate.batch_id}</strong><small>{gate.authority_path ?? gate.reason ?? 'qualification authority required'}{gate.blockers.length ? ` · ${gate.blockers.join(' · ')}` : ''}</small></p><div><b>{gate.summary.total ? `${gate.summary.built}/${gate.summary.total}` : '—'}</b><span>compile cells</span></div><div><b>{gate.satisfied ? gate.promotion_state.replaceAll('-', ' ') : 'campaign blocked'}</b><span>promotion</span></div></article>;
            })}
          </div>
        </section>}

        {machineValidation && <section className="operational-matrix-band validation-band">
          <div className="operational-band-title"><b>04</b><span><strong>Validation and hash discrimination</strong><small>Machine cohorts measure controlled width; held-out binaries test the corpus; HDI learns how strongly each compatible hash distinguishes provenance.</small></span><em>{machineValidation.summary.complete_libraries}/{machineValidation.summary.cohort_libraries} cohort · {ecologicalValidation?.summary.completed_cases ?? 0} ecological · HDI {hashDiscrimination?.summary.scored_signatures ?? '—'}</em></div>
          <div className="operational-validation-stack">
            <div className="operational-validation-row"><span className={`operational-state ${machineValidation.run.state === 'complete' ? 'ready' : ['queued', 'preparing-index', 'running', 'pausing', 'paused', 'interrupted'].includes(machineValidation.run.state) ? 'next' : machineValidation.readiness.eligible ? 'ready' : 'blocked'}`}>{['queued', 'preparing-index', 'running', 'pausing'].includes(machineValidation.run.state) ? machineValidation.run.state.replaceAll('-', ' ').toUpperCase() : ['paused', 'interrupted'].includes(machineValidation.run.state) ? 'PAUSED · RESUMABLE' : machineValidation.run.state === 'complete' ? 'MEASURED' : machineValidation.run.state === 'failed' && (machineValidation.run.expected_work_units ?? 0) > machineValidation.run.complete_work_units ? 'RETRY · RESUMABLE' : machineValidation.readiness.eligible ? 'READY TO RUN' : 'WAITING'}</span><p><strong>Machine validation · {machineValidation.id}</strong><small>{machineValidation.summary.exact_identities} live identities ({machineValidation.summary.width_delta_from_baseline >= 0 ? '+' : ''}{machineValidation.summary.width_delta_from_baseline} from baseline) · fixed RNG seed · {machineValidation.summary.composite_programs} composites</small></p><div><b>{machineValidation.run.expected_work_units ? `${machineValidation.run.complete_work_units}/${machineValidation.run.expected_work_units}` : machineValidation.summary.cohort_libraries - machineValidation.summary.complete_libraries}</b><span>{machineValidation.run.expected_work_units ? 'run units' : 'libraries to gate'}</span></div><div><b>{machineValidation.canary_gate.ready ? 'PASS' : `≈${machineValidation.planning.central_wall_hours.toFixed(0)}h`}</b><span>{machineValidation.canary_gate.ready ? 'canary gate' : 'planning wall'}</span></div></div>
            <div className="operational-validation-row"><span className={`operational-state ${ecologicalValidation?.corpus.materialized_generations ? 'ready' : 'blocked'}`}>{ecologicalValidation?.corpus.materialized_generations ? 'CORPUS READY' : 'NO CORPUS'}</span><p><strong>Ecological validation · held-out binaries</strong><small>{ecologicalValidation?.summary.imported_cases ?? 0} imports · {ecologicalValidation?.aggregate.measured_cases ?? 0} measured · entire compatible lane corpus · never execute imports</small></p><div><b>{ecologicalValidation?.aggregate.failure_summary.collisions ?? 0}</b><span>collisions</span></div><div><b>{ecologicalValidation?.aggregate.failure_summary.misses ?? 0}</b><span>misses</span></div></div>
            <div className="operational-validation-row"><span className={`operational-state ${hashDiscrimination?.readiness.ready_for_first_fit ? 'ready' : 'blocked'}`}>{hashDiscrimination?.readiness.ready_for_first_fit ? 'READY TO FIT' : 'WAITING HDI'}</span><p><strong>Hash Discrimination Index</strong><small>{hashDiscrimination?.readiness.complete_library_families ?? 0}/{hashDiscrimination?.readiness.required_library_families ?? 10} complete families · {noisyHashes?.summary.observed_hashes ?? 0} collision-bearing hashes · unweighted baseline preserved · no automatic filtering</small></p><div><b>{hashDiscrimination?.summary.scored_signatures ?? '—'}</b><span>scored hashes</span></div><div><b>{noisyHashes?.summary.confirmed_noisy ?? 0}</b><span>confirmed noisy</span></div></div>
          </div>
        </section>}

        <section className="operational-matrix-band retention-band">
          <div className="operational-band-title"><b>05</b><span><strong>Retention & garbage collection</strong><small>Terminal queue or validation → verified dry-run → bounded collection → worker recycle → memory audit.</small></span><em>{retention?.latest_plan ? `${retention.latest_plan.summary.actions.toLocaleString()} actions · ${formatBytes(retention.latest_plan.summary.recoverable_apparent_bytes)}` : 'awaiting dry-run'}</em></div>
          <div className="operational-retention-row"><span className={`operational-state ${retention?.latest_plan?.automatic_apply_eligible ? 'ready' : 'blocked'}`}>{retention?.latest_plan ? retention.latest_plan.automatic_apply_eligible ? 'AUTO ELIGIBLE' : 'MANUAL REVIEW' : 'NOT PLANNED'}</span><p><strong>{retention?.policy.authority_path ?? 'retention/policy.toml'}</strong><small>{retention?.latest_plan ? `${retention.latest_plan.summary.verified_successes.toLocaleString()} seals verified · ${retention.latest_plan.summary.preserved.toLocaleString()} protected · ${retention.latest_plan.summary.quarantined.toLocaleString()} quarantined` : 'content-addressed plan required before deletion'}</small></p><div><b>{retention?.latest_plan ? formatDurationNs(retention.latest_plan.estimated_apply_seconds * 1_000_000_000) : '—'}</b><span>estimated apply</span></div><div><b>{retention?.memory_cleanup.latest_session?.workers ? `${retention.memory_cleanup.latest_session.passed ?? 0}/${retention.memory_cleanup.latest_session.workers}` : '—'}</b><span>memory audits pass</span></div></div>
        </section>

        <div className="operational-gap-grid">
          <section className="operational-matrix-band unscheduled-band">
            <div className="operational-band-title"><b>06</b><span><strong>Buildable but unscheduled</strong><small>A reviewed recipe and source-capable route exist, but no active queue batch selects them.</small></span><em>{unscheduledRecipes.length}</em></div>
            <div className="operational-compact-list">
              {unscheduledRecipes.map(recipe => <article key={recipe.id}><span className="operational-state ready">READY</span><p><strong>{recipe.name} {recipe.version}</strong><small>{recipe.adapter} · {recipe.coverage}</small></p></article>)}
              {!unscheduledRecipes.length && <div className="operational-empty"><strong>No reviewed recipe is stranded</strong><small>Every currently buildable top-ten subject is represented in the active queue.</small></div>}
            </div>
          </section>

          <section className="operational-matrix-band recipe-gap-band">
            <div className="operational-band-title"><b>07</b><span><strong>No recipe yet</strong><small>Ranked family and source evidence exist, but no reviewed build recipe does.</small></span><em>{missingRecipeFamilies.length}</em></div>
            <div className="operational-compact-list">
              {missingRecipeFamilies.map(family => <article key={family.id}><span className="operational-state gap">RECIPE GAP</span><p><strong>#{family.rank} {family.label}</strong><small>{family.source_state} · {family.selection_evidence}</small></p></article>)}
              {!missingRecipeFamilies.length && <div className="operational-empty"><strong>Top-ten recipe set complete</strong><small>The broader C-family census is not promoted into this executable matrix until its family rows and source evidence are registered.</small></div>}
            </div>
          </section>

          <section className="operational-matrix-band toolchain-gap-band">
            <div className="operational-band-title"><b>08</b><span><strong>No executable toolchain yet</strong><small>Target/compiler demand exists, but neither an installed native route nor a source-capable cross route is registered.</small></span><em>{missingToolchainRequirements.length}</em></div>
            <div className="operational-compact-list">
              {missingToolchainRequirements.map(requirement => <article key={requirement.id}><span className="operational-state gap">{requirement.route_state.replaceAll('-', ' ')}</span><p><strong>{requirement.target_label} · {requirement.compiler_label}</strong><small>#{requirement.order} · {requirement.acquisition} · {requirement.worker_class}</small></p></article>)}
              {!missingToolchainRequirements.length && <div className="operational-empty"><strong>No toolchain gaps in the selected width</strong><small>Every demanded target/compiler pair has an executable route authority.</small></div>}
            </div>
          </section>
        </div>
        <footer><span>BUILT</span> means sealed output. <span>SCHEDULED</span> means present in the active TOML queue. <span>READY</span> means buildable but not queued. Gaps remain visible until their recipe or toolchain authority exists.</footer>
      </section>

      {selectedLanguage && <details className="panel matrix-detail-section" onToggle={event => setScopeOpen(event.currentTarget.open)}><summary><span><b>Scope and denominator</b><small>{selectedLanguage.label} family boundary, caveat and treatment-axis vocabulary</small></span><em>EXPAND</em></summary>{scopeOpen && <section className="language-matrix-contract"><div><span className={`language-state ${selectedLanguage.state}`}>{selectedLanguage.state.replaceAll('-', ' ')}</span><p className="panel-kicker">{selectedLanguage.label.toUpperCase()} DENOMINATOR</p><h3>{selectedLanguage.scope}</h3><p>{selectedLanguage.denominator}</p><small>{selectedLanguage.caveat}</small></div><div><span>TREATMENT AXES</span><div>{selectedLanguage.treatment_axes.map(axis => <em key={axis}>{axis}</em>)}</div></div></section>}</details>}

      {widthStudy && <details className="panel matrix-detail-section" onToggle={event => setWidthLaboratoryOpen(event.currentTarget.open)}><summary><span><b>Width laboratory and applicability map</b><small>{widthStudy.family_count} ranked families · {widthCompilation?.summary.executable_route_profile_pairs ?? 0} executable route/profile pairs · scaling controls</small></span><em>EXPAND</em></summary>{widthLaboratoryOpen && <WidthStudyPanel key={widthStudy.id} study={widthStudy} compilation={widthCompilation} capabilities={factory.capabilities} />}</details>}

      {selectedLanguageId !== 'c' && <div className="inline-warning language-registration-warning">The {selectedLanguage?.label} matrix is defined conceptually, but no screened family denominator, finite profile pack or executable recipe rows are registered. The empty rows below are deliberate—not zero coverage.</div>}

      <section className="plan-source-bar">
        <div><span className="source-glyph">T</span><p><strong>{selectedLanguageId === 'c' ? 'plans/priority-queue.toml' : `${selectedLanguage?.label ?? selectedLanguageId} execution authority not registered`}</strong><small>{selectedLanguageId === 'c' ? 'fidb-queue/v1 · batch order points to immutable fidb-plan/v1 requests' : 'conceptual language matrix · no queue cells or executable recipes'}</small></p></div>
        <span className="authority-badge">{selectedLanguageId === 'c' ? 'PRIORITY AUTHORITY' : 'DESIGN SCOPE'}</span>
      </section>

      <details className="panel matrix-detail-section crosspoint-drilldown" onToggle={event => setCrosspointOpen(event.currentTarget.open)}><summary><span><b>Full variable crosspoint and plan-draft editor</b><small>Cell-level families × routes × compilers × treatments × admission. Open only when you need to inspect or draft exact cells.</small></span><em>EXPAND</em></summary>{crosspointOpen && <div className="matrix-workspace">
        <section className="panel crosspoint-matrix-panel">
          <div className="matrix-main-header"><h2>Coverage crosspoints</h2><div className="matrix-live-summary"><span>RAW TREATMENT SPACE <strong>{rawNamedTreatmentSpace ? rawNamedTreatmentSpace.toLocaleString() : '—'}</strong><small>{selectedLanguageId === 'c' ? 'named C tuples / target / release; not a run plan' : 'finite profile pack not qualified'}</small></span><span>CANDIDATE PROFILES <strong>{languageProfiles.length || '—'}</strong><small>language-scoped · assumptions labelled</small></span><span>TARGET CONTEXTS <strong>{authority?.targets.length ?? '—'}</strong><small>{executableTargetCount} have a registered source route</small></span><span>DRAFT EXECUTIONS <strong>{desiredCellCount}</strong><small>TOML intent</small></span><span>QUEUEABLE <strong>{plannedCells}</strong><small>{selectedLanguageId === 'c' ? `${knownFactorCount} known factors · ${measuredFactorCount} observed` : 'no executable language pack'}</small></span><span>BUILT EVIDENCE <strong>{selectedLanguageId === 'c' ? builtCellIds.size : '—'}</strong><small>sealed cells · not yet coverage</small></span><span>ADMITTED COVERAGE <strong>—</strong><small>admission ledger not projected</small></span></div></div>
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
                    const possibilityOnly = column.kind === 'target' || column.kind === 'profile';
                    const compatible = column.kind === 'summary'
                      || column.kind === 'catalog'
                      || possibilityOnly
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
                    if (column.kind === 'catalog' || possibilityOnly) state = column.state;
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
                      if (possibilityOnly) return;
                      if (!compatible || catalogOnly) return setInspectedRecipe(recipe.id);
                      if (!recipeSelected) setSelectedRecipesOverride(current => [...(current ?? selectedRecipes), recipe.id]);
                      if (column.kind === 'route') toggleRoute(recipe.id, column.id);
                      else toggleFactor(recipe.id, column.id);
                    };
                    return <td className={`matrix-point-cell ${state}`} key={`${recipe.id}-${column.id}`}><button onClick={action} disabled={(!compatible && !routeRelevant) || possibilityOnly} aria-pressed={requested} title={`${recipe.name} × ${column.label}: ${catalogOnly && state === 'blocked' ? 'desired gap' : state}. ${catalogOnly ? recipe.gap : column.detail}`}><span>{state === 'unavailable' ? '—' : state === 'blocked' ? '!' : state === 'artifact-only' ? '◐' : state === 'built' ? '■' : state === 'running' ? '▶' : state === 'executable' ? 'E' : state === 'conceptual' ? 'C' : state === 'catalogued' ? 'K' : state === 'desired' ? 'D' : state === 'guarded' ? 'G' : state === 'observed' ? 'O' : state === 'recorded' ? '●' : state === 'unmodeled' ? '?' : state === 'summary' ? (column.kind === 'summary' ? (variableGroup.options.filter(option => option.kind === 'catalog' || (option.kind === 'route' ? (routeSelections[recipe.id] || []).includes(option.id) : (factorSelections[recipe.id] || []).includes(option.id))).length || '·') : '·') : requested ? '■' : '·'}</span></button></td>;
                  }))}</tr>;
                })}</Fragment>)}</Fragment>;
              })}</tbody>
            </table>
          </div>
          <div className="matrix-legend"><span><i className="conceptual" /> conceptual context</span><span><i className="catalogued" /> catalogued</span><span><i className="executable" /> executable route exists</span><span><i className="selected" /> selected</span><span><i className="queued" /> queued</span><span><i className="running" /> running</span><span><i className="built" /> sealed built</span><span><i className="blocked" /> blocked / guarded</span><span><i className="unavailable" /> incompatible</span><p>Possibility-space markers are not queue cells. Built means evidence-backed output, never merely a declared target.</p></div>
          {inspectedCatalogFactor && <aside className="matrix-factor-inspector"><div><span>KNOWN SENSITIVITY FACTOR</span><button onClick={() => setInspectedFactor(null)} aria-label="Close factor detail">×</button></div><h3>{inspectedCatalogFactor.label}</h3><p>{inspectedCatalogFactor.detail}</p><dl><div><dt>Catalogue ID</dt><dd>{inspectedCatalogFactor.id}</dd></div><div><dt>Group</dt><dd>{inspectedFactorGroup?.label || 'Sensitivity'}</dd></div><div><dt>Matrix status</dt><dd>{inspectedCatalogFactor.state === 'recorded' ? 'Recorded in resolved-cell provenance' : 'Known factor; no named selectable variant yet'}</dd></div><div><dt>Authority</dt><dd>sensitivity/factors.toml</dd></div></dl><small>The catalogue is intentionally extensible: report-backed factors are the current baseline, not a claim that every possible FID influence is already known.</small></aside>}
          {inspected && <aside className="recipe-provenance matrix-provenance"><div><span>{inspected.planEligible ? 'REVIEWED RECIPE PROVENANCE' : 'TIER 0 COVERAGE GAP'}</span><button onClick={() => setInspectedRecipe(null)} aria-label="Close provenance">×</button></div><h3>{inspected.name} <em>{inspected.version}</em></h3><p>{inspected.planEligible ? 'Immutable build identity comes from the reviewed recipe. Change the recipe TOML and re-resolve the plan to alter these fields.' : inspected.gap}</p><dl><div><dt>Authority</dt><dd>{inspected.authority}</dd></div><div><dt>Readiness</dt><dd>{inspected.coverage}</dd></div><div><dt>Batch / family</dt><dd>{inspected.batch} / {inspected.familyGroup}</dd></div><div><dt>Match context</dt><dd>{inspected.matchSet}</dd></div>{inspected.recipePath && <div><dt>Recipe</dt><dd>{inspected.recipePath}</dd></div>}{inspected.adapter && <div><dt>Mode / adapter</dt><dd>{inspected.mode} / {inspected.adapter}</dd></div>}{inspected.url && <div className="wide"><dt>Source URL</dt><dd>{inspected.url}</dd></div>}{inspected.sha256 && <div className="wide"><dt>SHA-256</dt><dd>{inspected.sha256}</dd></div>}</dl></aside>}
        </section>

        <aside className="plan-visualizer">
          <section className="panel cell-map-panel">
            <div className="panel-header"><h3>Execution map · {cells.length} base cells → {desiredCellCount} exact executions</h3><span className={blockedCells ? 'plan-state blocked' : 'plan-state ready'}>{blockedCells ? `${blockedCells} GAP` : 'COVERED'}</span></div>
            <div className="cell-summary"><div><span>DESIRED</span><strong>{desiredCellCount}</strong></div><div><span>QUEUEABLE</span><strong>{plannedCells}</strong></div><div><span>BLOCKED</span><strong>{blockedCells}</strong></div><div><span>OPTIONS</span><strong>{selectedFactorRows.length} / {allFactorOptions.length}</strong></div></div>
            <div className="cell-flow-head"><span>Recipe</span><span>Target + toolchain</span><span>Treatment</span><span>Analysis</span></div>
            <div className="visual-cell-list">
              {cells.map(cell => <div className={`visual-cell ${cell.status} ${cell.coverage || 'not-built'}`} key={cell.id}><span className="cell-status-icon">{cell.coverage === 'artifact-only' ? '◐' : cell.status === 'planned' ? '✓' : '!'}</span><div><strong>{cell.recipe}</strong><small>{cell.coverage === 'artifact-only' ? `artifact found · ${cell.batch}` : `${cell.route} · ${cell.batch}`}</small></div><b>→</b><div><strong>{cell.target}</strong><small>{cell.toolchain}</small></div><b>→</b><div><strong>{cell.treatment}</strong><small>× {combinationsForRecipe(cell.recipeId).length} exact factor tuples</small></div><b>→</b><div><strong>{cell.analysis}</strong><small>execution identity recorded</small></div></div>)}
              {!cells.length && <div className="empty-state"><span>◇</span><strong>No desired cells</strong><p>Select at least one recipe and compatible route.</p></div>}
            </div>
            {blockedCells > 0 && <div className="coverage-alert"><span>!</span><p><strong>Desired coverage is not silently discarded.</strong><small>{blockedCells} desired cells currently lack a registered treatment, source-capable toolchain, or guarded truth/admission path. They remain visible until those requirements exist.</small></p></div>}
          </section>

          <section className="panel malware-estimate-panel"><div className="panel-header"><h3>Timing evidence</h3><span className={timing?.eta ? 'plan-state ready' : 'plan-state'}>{timing?.eta ? 'MEASURED' : 'COLLECTING'}</span></div>{malwareRecipe ? <div className="malware-estimate-row"><span className="malware-glyph">M</span><div><strong>{malwareRecipe.name}</strong><small>{malwareRecipe.version} · {malwareRecipe.adapter}</small></div><p><span>KNOWN CELLS</span><strong>{malwareInventory.length}</strong></p><p><span>SEALED / LOOSE</span><strong>{malwareInventory.filter(([, row]) => row.state === 'built').length} / {malwareInventory.filter(([, row]) => row.state === 'artifact-only').length}</strong></p><p><span>QUEUE ETA</span><strong>{measuredEtaNs === null ? 'Collecting evidence' : formatDurationNs(measuredEtaNs)}</strong><small>{timing?.eta?.sample_count ? `${timing.eta.sample_count} measured workflows` : 'no historical estimate yet'}</small></p></div> : <div className="empty-state"><span>◇</span><strong>No reviewed ground-truth recipe</strong><p>Add one to the recipe authority before planning it.</p></div>}</section>

          <section className="panel execution-queue-panel"><div className="panel-header"><h3>Priority queue draft · batch × cell × variance</h3><span className="plan-state">TOML INTENT</span></div><div className="queue-controls single"><label><span>VARIANCE ORDER WITHIN EACH BATCH</span><select value={queueStrategy} onChange={event => setQueueStrategyOverride(event.target.value)}><option value="recipe-then-variant">recipe, then variance</option><option value="variant-then-recipe">variance, then recipe</option></select></label><button onClick={() => setQueueMessage(`Priority queue draft updated with ${executionQueue.length} execution identities in current batch order.`)}>Update priority queue draft</button></div>{queueMessage && <div className="queue-message">✓ {queueMessage}</div>}<div className="queue-state-summary"><div><span>QUEUEABLE</span><strong>{executionQueue.filter(row => row.state === 'queueable').length}</strong></div><div><span>BUILT</span><strong>{builtExecutions}</strong></div><div><span>ARTIFACT ONLY</span><strong>{cells.filter(cell => cell.coverage === 'artifact-only').length}</strong></div><div><span>UNBUILT / BLOCKED</span><strong>{executionQueue.filter(row => row.state === 'blocked').length}</strong></div></div><div className="execution-queue-list">{executionQueue.slice(0, 8).map(row => <div className={`execution-queue-row ${row.state}`} key={`${row.cell.id}-${row.position}`}><b>{String(row.position).padStart(3, '0')}</b><div><strong>{row.cell.recipe}</strong><small>{row.cell.target} · {row.combination.map(option => option.label).join(' / ') || 'route defaults'}</small></div><em>{row.cell.batch}</em><span>{row.cell.coverage === 'built' ? 'built' : row.cell.coverage === 'artifact-only' ? 'artifact only' : row.state}</span></div>)}{executionQueue.length > 8 && <div className="queue-remainder">+ {executionQueue.length - 8} more ordered execution identities</div>}</div></section>

          {tomlOpen && <section className="panel toml-panel"><div className="panel-header"><h3>TOML request</h3><span className={draftIsCurrent ? 'plan-state ready' : 'plan-state'}>{draftIsCurrent ? 'RESOLVED' : 'DRAFT'}</span></div><pre>{toml}</pre><div className="draft-controls"><label><span>DRAFT NAME</span><input value={draftName} onChange={event => { setDraftName(event.target.value); setDraftMessage('Draft changed; resolve it again before saving.'); }} spellCheck={false} /></label><div><button onClick={() => void resolveDraft()} disabled={factory.busyAction !== null || !plannedRecipeRows.length}>{factory.busyAction === 'plan-draft-resolve' ? 'Resolving…' : 'Resolve against authority'}</button><button className="primary" onClick={() => void saveDraft()} disabled={factory.busyAction !== null || !draftIsCurrent}>{factory.busyAction === 'plan-draft-save' ? 'Saving…' : savedAuthorityDraft || savedDraftSha256 ? 'Save validated update' : 'Save validated draft'}</button></div><p className={draftIsCurrent ? 'valid' : ''}>{draftResult && !draftIsCurrent ? 'Draft changed; resolve it again before saving.' : draftMessage}</p></div><div className="toml-footer"><span>Only catalog identities are accepted; saving does not enqueue or execute the plan</span><code>{savedAuthorityDraft?.path ?? 'plans/drafts/&lt;name&gt;.toml'}</code></div></section>}
        </aside>
      </div>}</details>
    </div>
  );
}

function PerformanceView({ factory }: { factory: FactoryApiState }) {
  return <div className="view-stack performance-view">
    <ViewIntro
      kicker="HOST-AWARE EXECUTION POLICY"
      title="Performance"
      action={<button className="secondary-action" onClick={() => void factory.refresh()} disabled={factory.connection === 'connecting'}>{factory.connection === 'live' ? 'Refresh' : 'Retry connection'}</button>}
    />
    <PanelReadWarning factory={factory} endpoints={['authority', 'capabilities', 'hash-analysis-backend', 'fid-matching-backend']} />
    {factory.authority?.performance_profiles
      ? <PerformanceProfilesPanel catalog={factory.authority.performance_profiles} capabilities={factory.capabilities} snapshot={factory.snapshot} />
      : <section className="panel"><div className="empty-state"><span>◇</span><strong>Performance authority unavailable</strong><p>Reconnect the local API to load the reviewed TOML profiles.</p></div></section>}
    <HashAnalysisBackendPanel factory={factory} />
    <FidMatchingBackendPanel factory={factory} />
  </div>;
}

function RetentionView({ factory }: { factory: FactoryApiState }) {
  const retention = factory.retention;
  const [message, setMessage] = useState('');
  if (!retention) return <div className="view-stack"><ViewIntro kicker="RETENTION" title="Retention & garbage collection" /><PanelReadWarning factory={factory} endpoints={['retention']} /><section className="panel"><div className="empty-state"><span>◇</span><strong>Retention status unavailable</strong><p>Reconnect the local API to read retention/policy.toml.</p></div></section></div>;
  const plan = retention.latest_plan;
  const run = retention.last_run;
  const memory = retention.memory_cleanup.latest_session;
  const policy = retention.policy;
  const planning = factory.busyAction === 'retention-plan';
  const applying = factory.busyAction === 'retention-apply';
  const buildPlan = async () => {
    setMessage('Verifying seals, ledger references and candidate bytes…');
    try {
      const result = await factory.planRetention();
      setMessage(`Dry-run ${result.latest_plan?.plan_digest.slice(0, 12) ?? ''} is ready.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Dry-run failed.');
    }
  };
  const applyPlan = async () => {
    if (!plan) return;
    const approved = window.confirm(`Apply retention plan ${plan.plan_digest}?\n\n${plan.summary.source_directories.toLocaleString()} directories · ${formatBytes(plan.summary.recoverable_apparent_bytes)} selected. Preserved and quarantined paths are excluded.`);
    if (!approved) return;
    setMessage(`Applying ${plan.plan_digest.slice(0, 12)}…`);
    try {
      const result = await factory.applyRetention(plan.plan_digest);
      setMessage(`Collected ${formatBytes(result.last_run?.filesystem_free_bytes_delta ?? 0)} of filesystem space.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Retention apply failed.');
    }
  };
  const exampleRow = (row: Record<string, unknown>, index: number) => <article key={`${String(row.kind)}-${String(row.job_id ?? row.run_id ?? row.path)}-${index}`}><span>{String(row.kind ?? 'evidence')}</span><p><strong>{String(row.job_id ?? row.run_id ?? row.path ?? 'unknown')}</strong><small>{String(row.reason ?? row.path ?? '')}</small></p></article>;
  return <div className="view-stack retention-view">
    <ViewIntro kicker="POST-SESSION" title="Retention & garbage collection" action={<div className="view-intro-actions"><button className="secondary-action" onClick={() => void buildPlan()} disabled={planning || applying}>{planning ? 'Scanning…' : 'Build dry-run plan'}</button><button className="primary-action" onClick={() => void applyPlan()} disabled={!plan || planning || applying}>{applying ? 'Collecting…' : 'Apply exact plan'}</button></div>} />
    <PanelReadWarning factory={factory} endpoints={['retention']} />

    <section className="retention-metrics">
      <article className="panel"><span>SELECTED</span><strong>{plan ? formatBytes(plan.summary.recoverable_apparent_bytes) : '—'}</strong><small>{plan ? `${formatBytes(plan.summary.validation_recoverable_apparent_bytes ?? 0)} validation transient · ${(plan.summary.validation_composite_files ?? 0).toLocaleString()} composites · ${plan.summary.actions.toLocaleString()} actions` : 'build a dry-run'}</small></article>
      <article className="panel"><span>PRESERVED</span><strong>{plan?.summary.preserved.toLocaleString() ?? '—'}</strong><small>{plan ? `${plan.summary.verified_successes.toLocaleString()} seals · ${(plan.summary.verified_validation_runs ?? 0).toLocaleString()} validation runs verified` : 'no plan'}</small></article>
      <article className="panel"><span>QUARANTINED</span><strong>{plan?.summary.quarantined.toLocaleString() ?? '—'}</strong><small>excluded from deletion</small></article>
      <article className="panel"><span>ESTIMATED APPLY</span><strong>{plan ? formatDurationNs(plan.estimated_apply_seconds * 1_000_000_000) : '—'}</strong><small>automatic ceiling {formatDurationNs(policy.automation.maximum_estimated_seconds * 1_000_000_000)}</small></article>
      <article className="panel"><span>LAST FREED</span><strong>{run ? formatBytes(run.filesystem_free_bytes_delta) : '—'}</strong><small>{run ? `${run.actions_completed.toLocaleString()} actions · ${formatDurationNs(run.duration_ns)}` : 'no apply recorded'}</small></article>
      <article className="panel"><span>MEMORY RELEASE</span><strong>{memory?.reclaimed_rss_bytes !== undefined ? formatBytes(memory.reclaimed_rss_bytes) : '—'}</strong><small>{memory?.workers ? `${memory.passed ?? 0}/${memory.workers} fresh workers passed` : 'awaiting a worker recycle'}</small></article>
    </section>

    <section className="panel retention-policy-panel">
      <header><div><h3>{policy.name}</h3><code>{policy.authority_path} · {policy.authority_sha256.slice(0, 16)}… {plan ? `· ${plan.scope}` : ''}</code></div><span className={`validation-state ${plan?.automatic_apply_eligible ? 'ready' : 'waiting'}`}>{plan ? plan.automatic_apply_eligible ? 'AUTO ELIGIBLE' : 'MANUAL REVIEW' : 'NO PLAN'}</span></header>
      <div className="retention-flow">
        <article><b>01</b><p><strong>TERMINAL RUN</strong><small>{policy.automation.triggers.join(' · ')}</small></p></article>
        <article><b>02</b><p><strong>DRY-RUN</strong><small>seal + ledger + byte scan</small></p></article>
        <article><b>03</b><p><strong>PROTECT</strong><small>holds + lane-import boundary</small></p></article>
        <article><b>04</b><p><strong>COLLECT</strong><small>failure bundles + build/validation scratch</small></p></article>
        <article><b>05</b><p><strong>RECYCLE</strong><small>{policy.automation.worker_action} long-lived workers</small></p></article>
        <article><b>06</b><p><strong>VERIFY + PARK</strong><small>fresh RSS + JVM state · {policy.memory_cleanup.park_poll_seconds}s wake check</small></p></article>
      </div>
      <div className="retention-contract-grid"><article><span>SUCCESS</span><strong>{policy.success.preserve_until_lane_imported ? 'PRESERVE UNTIL LANE RECEIPT' : 'POLICY CONTROLLED'}</strong><small>required: {policy.success.required_result_artifacts.join(' · ')}</small></article><article><span>VALIDATION</span><strong>{policy.validation.prune_composite_binaries ? 'HASH + RELATION EVIDENCE' : 'COMPOSITES RETAINED'}</strong><small>composites prune only after {policy.validation.required_signature_evidence_schema} seals</small></article><article><span>FAILURES</span><strong>{policy.failure.retain_latest_evidence_bundle ? 'FINAL EVIDENCE BUNDLE' : 'PRESERVED WHOLE'}</strong><small>identical retries {policy.failure.collapse_identical_retries ? 'collapse' : 'remain whole'}</small></article><article><span>AUTOMATION</span><strong>{policy.automation.enabled ? policy.automation.mode.toUpperCase() : 'DISABLED'}</strong><small>always dry-run first · ≤{policy.automation.maximum_estimated_seconds}s</small></article></div>
      <footer><code>{plan ? `${plan.path} · ${plan.plan_digest}` : 'No content-addressed plan yet'}</code><span>{message}</span></footer>
    </section>

    <section className="panel retention-memory-panel">
      <header><div><h3>Post-recycle memory</h3><code>{memory?.session_id ?? 'No audited recycle session'}</code></div><span className={`validation-state ${memory && (memory.warnings ?? 0) === 0 && (memory.unreadable_reports ?? 0) === 0 ? 'ready' : 'waiting'}`}>{memory ? (memory.warnings ?? 0) === 0 && (memory.unreadable_reports ?? 0) === 0 ? 'VERIFIED' : 'REVIEW' : 'WAITING'}</span></header>
      <div className="retention-memory-summary">
        <article><span>BEFORE</span><strong>{memory?.before_rss_bytes !== undefined ? formatBytes(memory.before_rss_bytes) : '—'}</strong></article>
        <article><span>AFTER</span><strong>{memory?.after_rss_bytes !== undefined ? formatBytes(memory.after_rss_bytes) : '—'}</strong></article>
        <article><span>RELEASED</span><strong>{memory?.reclaimed_rss_bytes !== undefined ? formatBytes(memory.reclaimed_rss_bytes) : '—'}</strong></article>
        <article><span>THRESHOLD / WORKER</span><strong>{formatBytes(retention.memory_cleanup.post_recycle_rss_warning_bytes)}</strong></article>
        <article><span>JVM / RSS CHECKS</span><strong>{memory?.workers ? `${memory.passed ?? 0} pass · ${memory.warnings ?? 0} warn` : '—'}</strong></article>
      </div>
      <div className="retention-memory-workers">{memory?.reports?.map(report => <article key={report.worker_id}><span className={`operational-state ${report.state === 'passed' ? 'ready' : 'blocked'}`}>{report.state.toUpperCase()}</span><p><strong>{report.worker_id}</strong><small>{formatBytes(report.before.rss_bytes)} → {formatBytes(report.after.rss_bytes)} · JVM {report.after.embedded_jvm_started === false ? 'absent' : 'unverified'}</small></p><b>{formatBytes(report.reclaimed_rss_bytes)}</b></article>)}{!memory?.reports?.length && <div className="operational-empty"><strong>No recycle audit yet</strong></div>}</div>
    </section>

    <section className="retention-evidence-grid">
      <article className="panel"><header><h3>Protected evidence</h3><span>{plan?.summary.preserved ?? 0}</span></header><div className="retention-example-list">{plan?.preserved_examples.map(exampleRow)}{!plan?.preserved_examples.length && <div className="operational-empty"><strong>No sampled holds</strong></div>}</div></article>
      <article className="panel"><header><h3>Quarantine</h3><span>{plan?.summary.quarantined ?? 0}</span></header><div className="retention-example-list">{plan?.quarantine_examples.map(exampleRow)}{!plan?.quarantine_examples.length && <div className="operational-empty"><strong>No quarantined paths</strong></div>}</div></article>
    </section>
  </div>;
}

function ExportView({ factory }: { factory: FactoryApiState }) {
  const status = factory.exportStatus;
  const population = status?.population;
  const releaseReady = status?.ready ?? false;
  const buildBusy = factory.busyAction === 'export-build';
  const previewBusy = factory.busyAction === 'export-preview';
  const safeguardBusy = factory.busyAction === 'export-safeguard';
  const safeguardReady = status?.safeguard.state === 'current';
  const generation = status?.hash_quality.generation;
  const completeness = population && population.expected > 0
    ? Math.round((population.present / population.expected) * 100)
    : 0;
  const runPreview = () => void factory.previewExport().catch(() => undefined);
  const runSafeguard = () => void factory.safeguardExport().catch(() => undefined);
  const runBuild = () => void factory.buildExport().catch(() => undefined);

  return <div className="view-stack export-view">
    <ViewIntro
      kicker="PORTABLE DATABASE RELEASES"
      title="Export"
      action={<div className="view-intro-actions"><button className="secondary-action" onClick={runPreview} disabled={previewBusy || safeguardBusy || buildBusy}>{previewBusy ? 'Checking…' : 'Preview manifest'}</button><button className="secondary-action" onClick={runSafeguard} disabled={!status?.actions.safeguard || previewBusy || safeguardBusy || buildBusy}>{safeguardBusy ? 'Safeguarding…' : safeguardReady ? 'Refresh safeguard' : 'Safeguard inputs'}</button><button className="primary-action" onClick={runBuild} disabled={!releaseReady || previewBusy || safeguardBusy || buildBusy}>{buildBusy ? 'Building…' : 'Build export'}</button></div>}
    />
    <PanelReadWarning factory={factory} endpoints={['export']} />

    <section className="export-metrics">
      <article className="panel"><span>FIDBF IDENTITIES</span><strong>{population ? `${population.present.toLocaleString()} / ${population.expected.toLocaleString()}` : '—'}</strong><small>{status ? `${completeness}% complete · ${population?.missing.toLocaleString()} missing` : 'loading export authority'}</small></article>
      <article className="panel"><span>LIBRARIES COMPLETE</span><strong>{population ? `${population.libraries_complete} / ${population.libraries_expected}` : '—'}</strong><small>{population ? `${population.routes} routes × ${population.treatments} treatments` : 'exact width pending'}</small></article>
      <article className="panel"><span>RAW FIDBF SIZE</span><strong>{population ? formatBytes(population.raw_bytes) : '—'}</strong><small>before tar.zst compression</small></article>
      <article className="panel"><span>HASH EVIDENCE</span><strong>{generation ? generation.signatures.toLocaleString() : '—'}</strong><small>{generation ? `generation ${generation.ordinal} · ${generation.owners} owners` : status?.hash_quality.state.replaceAll('-', ' ') ?? 'loading'}</small></article>
      <article className="panel"><span>PACKAGE</span><strong>{status?.release.exists ? formatBytes(status.release.bytes) : 'NOT BUILT'}</strong><small>{status?.release.output_path ?? 'output path loading'}</small></article>
      <article className={`panel ${releaseReady ? 'ready' : 'blocked'}`}><span>EXPORT STATE</span><strong>{releaseReady ? 'READY' : 'BLOCKED'}</strong><small>{releaseReady ? 'all release gates pass' : status?.blockers[0] ?? 'authority loading'}</small></article>
    </section>

    <section className="panel export-assembly-panel">
      <header><div><h3>Release assembly</h3><code>{status?.authority.path ?? 'export/c10-fidbf-v1.toml'}</code></div><span className={`validation-state ${releaseReady ? 'ready' : 'waiting'}`}>{releaseReady ? 'PACKAGE INPUT READY' : `${population?.missing ?? '—'} FIDBF MISSING`}</span></header>
      <div className="export-assembly-flow">
        <article className={population?.missing === 0 ? 'ready' : 'waiting'}><b>01</b><p><strong>FIDBF POPULATION</strong><small>{population ? `${population.present.toLocaleString()} exact sealed identities` : 'loading'}</small></p></article>
        <article className={safeguardReady ? 'ready' : status?.actions.safeguard ? 'waiting' : 'blocked'}><b>02</b><p><strong>SAFEGUARD SOURCE</strong><small>{safeguardReady ? 'ledger snapshot + 2,220-file digest receipt' : status?.safeguard.live_jobs ? `${status.safeguard.live_jobs} active jobs must finish` : 'run before packaging'}</small></p></article>
        <article className={status?.compatibility.state === 'ready' ? 'ready' : 'blocked'}><b>03</b><p><strong>CATALOGUE + COMPATIBILITY</strong><small>identity lookup and lane-selection registry</small></p></article>
        <article className={status?.hash_quality.state === 'ready' && status?.validation.state === 'ready' ? 'ready' : 'blocked'}><b>04</b><p><strong>QUALITY EVIDENCE</strong><small>{generation ? `${generation.signatures.toLocaleString()} signatures + C10 validation` : 'sidecars unavailable'}</small></p></article>
        <article className={status ? 'ready' : 'waiting'}><b>05</b><p><strong>MANIFEST + SHA-256</strong><small>human + TOML manifests bind every member</small></p></article>
        <article className={status?.release.exists ? 'ready' : releaseReady ? 'waiting' : 'blocked'}><b>06</b><p><strong>BUILD + REOPEN</strong><small>{status?.release.exists ? `${formatBytes(status.release.bytes)} verified` : 'package only after safeguard'}</small></p></article>
      </div>
    </section>

    <div className="export-layout">
      <section className="panel export-contract-panel">
        <div className="panel-header"><h3>Package contents</h3><span className="plan-state">{status?.release.package_format.toUpperCase() ?? '—'}</span></div>
        <div className="export-contract-list">
          <article><span className={`operational-state ${population?.missing === 0 ? 'complete' : 'blocked'}`}>{population?.missing === 0 ? 'COMPLETE' : 'INCOMPLETE'}</span><p><strong>Raw Ghidra FID databases</strong><small>one `.fidbf` for each library × route × treatment identity</small></p><code>fidbf/*.fidbf</code></article>
          <article><span className={`operational-state ${safeguardReady ? 'complete' : 'blocked'}`}>{safeguardReady ? 'FROZEN' : 'REQUIRED'}</span><p><strong>Source safeguard</strong><small>consistent ledger snapshot plus verified identity, artifact, seal and retention receipt</small></p><code>evidence/source-safeguard.json</code></article>
          <article><span className="operational-state complete">GENERATED</span><p><strong>Artifact catalogue</strong><small>library, route, treatment, source, toolchain, seal and digest joins</small></p><code>index/catalogue.sqlite3</code></article>
          <article><span className={`operational-state ${status?.hash_quality.state === 'ready' ? 'complete' : 'blocked'}`}>{status?.hash_quality.state === 'ready' ? 'AVAILABLE' : 'BLOCKED'}</span><p><strong>Hash-quality evidence</strong><small>cross-library ownership and validation observations remain separate from raw FID</small></p><code>index/hash-quality.sqlite3</code></article>
          <article><span className={`operational-state ${status?.validation.state === 'ready' ? 'complete' : 'blocked'}`}>{status?.validation.state === 'ready' ? 'AVAILABLE' : 'BLOCKED'}</span><p><strong>Matching report</strong><small>archive + linked C10 precision, recall and error evidence</small></p><code>validation/*.json</code></article>
          <article><span className={`operational-state ${status?.compatibility.state === 'ready' ? 'complete' : 'blocked'}`}>{status?.compatibility.state === 'ready' ? 'AVAILABLE' : 'BLOCKED'}</span><p><strong>Compatibility registry</strong><small>{status?.compatibility.path ?? 'lanes/registry.toml'}</small></p><code>authority/lanes.toml</code></article>
          <article><span className="operational-state complete">GENERATED</span><p><strong>Release manifests and checksums</strong><small>human inventory plus member paths, bytes, SHA-256, schema and generation identity</small></p><code>manifest.md + release.toml + checksums</code></article>
        </div>
      </section>

      <section className="panel export-release-panel">
        <div className="panel-header"><h3>Release controls</h3><span className="plan-state">{releaseReady ? 'READY' : 'BLOCKED'}</span></div>
        <dl><div><dt>Release ID</dt><dd>{status?.release.id ?? '—'}</dd></div><div><dt>Output path</dt><dd>{status?.release.output_path ?? '—'}</dd></div><div><dt>Package format</dt><dd>{status?.release.package_format ?? '—'}</dd></div><div><dt>Authority</dt><dd>{status?.authority.path ?? '—'}</dd></div><div><dt>Authority SHA-256</dt><dd><code>{status?.authority.sha256 ? `${status.authority.sha256.slice(0, 16)}…` : '—'}</code></dd></div><div><dt>Historical retries</dt><dd>{population?.duplicate_completed_identities.toLocaleString() ?? '—'} recorded; newest seal selected</dd></div></dl>
        <div className="export-noise-key"><span>HASH-QUALITY GENERATION</span><code>{generation?.digest ?? 'not available'}</code><small>{status?.hash_quality.path ?? 'sidecar unavailable'} · signatures may associate with multiple libraries</small></div>
        {!!status?.blockers.length && <div className="export-blockers">{status.blockers.map(blocker => <p key={blocker}>{blocker}</p>)}</div>}
        <div className="export-control-actions"><button className="secondary-action" onClick={runPreview} disabled={previewBusy || safeguardBusy || buildBusy}>{previewBusy ? 'Checking…' : 'Preview manifest'}</button><button className="secondary-action" onClick={runSafeguard} disabled={!status?.actions.safeguard || previewBusy || safeguardBusy || buildBusy}>{safeguardBusy ? 'Safeguarding…' : safeguardReady ? 'Refresh safeguard' : 'Safeguard inputs'}</button><button className="primary-action" onClick={runBuild} disabled={!releaseReady || previewBusy || safeguardBusy || buildBusy}>{buildBusy ? 'Building package…' : 'Build package'}</button></div>
      </section>
    </div>

    <section className="panel export-lanes-panel">
      <div className="panel-header"><h3>C10 artifact completeness</h3><span className="plan-state">{population ? `${population.libraries_complete}/${population.libraries_expected} COMPLETE` : 'LOADING'}</span></div>
      <div>{status?.libraries.map(library => <article key={library.id}><span className={`operational-state ${library.complete ? 'complete' : 'blocked'}`}>{library.complete ? 'COMPLETE' : `${library.missing} MISSING`}</span><p><strong>{library.rank}. {library.label}</strong><small>{library.id}@{library.version}</small></p><div><b>{library.present} / {library.expected}</b><span>FIDBF identities</span></div><div><b>{formatBytes(library.bytes)}</b><span>raw size</span></div></article>)}{!status?.libraries.length && <div className="operational-empty"><strong>Export authority unavailable</strong><small>Reconnect the local API.</small></div>}</div>
    </section>
  </div>;
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
      title="Timing & throughput"
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
        <div className="panel-header"><h3>Active attempts</h3><span className={activeSpans.length ? 'timing-live-badge' : 'timing-muted-badge'}>{activeSpans.length ? 'LIVE' : 'IDLE'}</span></div>
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
        <div className="panel-header"><h3>Recent measurements</h3><span className="timing-muted-badge">LAST {measuredRecent.length}</span></div>
        <div className="timing-recent-list">
          {measuredRecent.map(span => <div key={span.stage_attempt_id}><span className="timing-stage-glyph">{span.sequence}</span><p><strong>{stageLabel(span.stage)}</strong><small>{span.job_id.slice(0, 12)} · attempt {span.attempt_number} · {span.worker_id}</small></p><b>{formatDurationNs(span.duration_ns)}</b></div>)}
          {!measuredRecent.length && <div className="empty-state timing-empty"><span>◇</span><strong>Collecting stage evidence</strong><p>Completed monotonic spans will appear here; estimated and interrupted values are excluded.</p></div>}
        </div>
      </article>
    </section>

    <section className="timing-aggregate-grid">
      <article className="panel timing-table-panel">
        <div className="panel-header"><h3>Stage distributions · p50 / p90</h3><span className="timing-source-badge">WORKER MONOTONIC</span></div>
        <div className="timing-distribution-table">
          <div className="timing-distribution-head"><span>Stage</span><span>Samples</span><span>p50</span><span>p90</span><span>Mean</span><span>Range</span></div>
          {(timing?.stages ?? []).flatMap(row => row.sample_count > 0 && row.duration_ns ? [<div className="timing-distribution-row" key={row.stage}><strong>{stageLabel(row.stage)}</strong><span>{row.sample_count}</span><b>{formatDurationNs(row.duration_ns.p50)}</b><b>{formatDurationNs(row.duration_ns.p90)}</b><span>{formatDurationNs(row.duration_ns.mean)}</span><small>{formatDurationNs(row.duration_ns.min)} – {formatDurationNs(row.duration_ns.max)}</small></div>] : [])}
          {!(timing?.stages ?? []).some(row => row.sample_count > 0 && row.duration_ns) && <div className="empty-state timing-empty"><span>◇</span><strong>No completed stage distribution</strong><p>p50 and p90 require completed worker-monotonic samples.</p></div>}
        </div>
      </article>

      <article className="panel timing-table-panel">
        <div className="panel-header"><h3>Workflow distributions</h3><span className="timing-source-badge wall">COORDINATOR CLOCK</span></div>
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
        <div className="panel-header"><h3>CPU &amp; memory</h3><span className="timing-source-badge">MEASURED SPANS</span></div>
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
        <div className="panel-header"><h3>Retries &amp; failures</h3><span className={retryOrFailureAttempts.length || failedSpans.length || regressedClockSpans.length ? 'timing-warning-badge' : 'timing-muted-badge'}>{retryOrFailureAttempts.length + failedSpans.length + regressedClockSpans.length}</span></div>
        <div className="timing-diagnostic-list">
          {retryOrFailureAttempts.slice(0, 8).map(attempt => <AttemptTimingRow attempt={attempt} now={coordinatorNow} key={`attempt-${attempt.attempt_id}`} />)}
          {failedSpans.slice(0, 8).map(span => <div key={`span-${span.stage_attempt_id}`}><span className={`timing-result ${span.state}`}>{span.state}</span><p><strong>{stageLabel(span.stage)}</strong><small>{span.job_id.slice(0, 12)} · attempt {span.attempt_number} · {span.duration_source ?? 'no duration source'}</small></p><b>{formatDurationNs(span.duration_ns)}</b></div>)}
          {regressedClockSpans.slice(0, 8).map(span => <div key={`clock-${span.stage_attempt_id}`}><span className="timing-result interrupted">clock</span><p><strong>{stageLabel(span.stage)}</strong><small>{span.job_id.slice(0, 12)} · UTC boundary regressed; monotonic duration remains authoritative</small></p><b>{formatDurationNs(span.duration_ns)}</b></div>)}
          {!retryOrFailureAttempts.length && !failedSpans.length && !regressedClockSpans.length && <div className="empty-state timing-empty"><span>✓</span><strong>No retry or failure timing</strong><p>This is an empty evidence set, not a claim that production runs have succeeded.</p></div>}
        </div>
      </article>

      <article className="panel timing-eta-panel">
        <div className="panel-header"><h3>Queue ETA</h3><span className={etaEvidence ? 'timing-source-badge' : 'timing-muted-badge'}>{etaEvidence ? 'AVAILABLE' : 'COLLECTING'}</span></div>
        {etaEvidence ? <div className="timing-eta-body"><div><span>p50 remaining</span><strong>{formatDurationNs(etaP50)}</strong></div><div><span>p90 remaining</span><strong>{formatDurationNs(etaP90)}</strong></div><div><span>Sample count</span><strong>{eta.sample_count}</strong></div><div><span>Confidence</span><strong>{eta.confidence ?? 'not labelled'}</strong></div>{eta.projected_completion_at && <p>Projected completion: <b>{formatStartedAt(eta.projected_completion_at)}</b></p>}</div> : <div className="empty-state timing-empty eta"><span>⌁</span><strong>Collecting evidence</strong><p>The UI will not estimate completion from cell counts or a fixed multiplier. ETA appears only when the coordinator returns a measured model and sample count.</p></div>}
      </article>
    </section>
  </div>;
}

function PerformanceProfilesPanel({ catalog, capabilities, snapshot }: { catalog: PerformanceProfiles; capabilities: FactoryCapabilities | null; snapshot: CoordinatorSnapshot | null }) {
  const activeProfile = snapshot?.performance_profile ?? null;
  const [selectedId, setSelectedId] = useState(activeProfile?.id ?? catalog.default_profile);
  const [copied, setCopied] = useState(false);
  const selected = catalog.profiles.find(profile => profile.id === selectedId) ?? catalog.profiles[0];
  if (!selected) return null;
  const host = capabilities?.host;
  const automatic = capabilities?.automatic_performance;
  const effective = selected.id === 'auto' ? automatic?.effective_settings : selected.settings;
  const hostMemoryMib = host?.memory_bytes ? Math.floor(host.memory_bytes / 1024 / 1024) : null;
  const activeMode = activeProfile
    ? activeProfile.id === 'auto' || activeProfile.resolution
      ? 'automatic · resolved and frozen'
      : 'fixed TOML profile'
    : 'no queue profile bound';
  const displaySetting = (name: string, value: number | null | undefined) => {
    if (value === null || value === undefined) return name === 'ghidra_core_limit' ? 'host default' : '—';
    return name === 'ghidra_heap_mib' ? `${value.toLocaleString()} MiB` : value.toLocaleString();
  };
  const settingRows = automatic ? [
    ['workers', 'Cell workers', automatic.effective_settings.workers, activeProfile?.settings.workers],
    ['build_jobs_per_cell', 'Build jobs / cell', automatic.effective_settings.build_jobs_per_cell, activeProfile?.settings.build_jobs_per_cell],
    ['ghidra_heap_mib', 'JVM heap ceiling', automatic.effective_settings.ghidra_heap_mib, activeProfile?.settings.ghidra_heap_mib],
    ['ghidra_core_limit', 'Ghidra core limit', automatic.effective_settings.ghidra_core_limit, activeProfile?.settings.ghidra_core_limit],
  ].map(([name, label, automaticValue, activeValue]) => {
    const isAutomatic = activeProfile?.id === 'auto' || Boolean(activeProfile?.resolution);
    const changed = activeValue !== automaticValue;
    return {
      name: String(name),
      label: String(label),
      automaticValue: automaticValue as number,
      activeValue: activeValue as number | null | undefined,
      state: !activeProfile ? 'unbound' : isAutomatic ? 'auto-resolved' : changed ? 'TOML override' : 'fixed · same as auto',
      tone: !activeProfile ? 'cold' : changed && !isAutomatic ? 'warning' : 'ready',
    };
  }) : [];
  const command = `fidb-poc run-width --project-root . --performance-profile ${selected.id}`;
  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  const qualificationTone = selected.qualification === 'measured-openssl'
    ? 'ready'
    : selected.qualification === 'derived-from-measured-openssl'
      ? 'warning'
      : 'cold';
  const linked = catalog.linked_reference;
  const linkedProfile = linked?.selected_profile;
  return <section className="panel performance-profile-panel">
    <div className="panel-header"><h3>Host policy · {catalog.authority_path}</h3><span className="authority-badge">TOML SOURCE OF TRUTH</span></div>
    <div className="performance-host-strip">
      <article><span>DETECTED CPU SPLIT</span><strong>{host ? `${host.physical_cores} physical / ${host.logical_cpus} logical` : 'Waiting for API'}</strong><small>{host ? `${host.smt_siblings} SMT siblings · ${host.threads_per_core.toFixed(2)} threads/core · ${host.system} / ${host.machine}` : 'capability probe pending'}</small></article>
      <article><span>OS-VISIBLE MEMORY</span><strong>{host?.memory_bytes ? formatBytes(host.memory_bytes) : '—'}</strong><small>{hostMemoryMib ? `${hostMemoryMib.toLocaleString()} MiB total · ${formatBytes(host?.available_memory_bytes ?? 0)} currently available` : 'capability probe pending'}</small></article>
      <article><span>AUTO BASELINE</span><strong>{automatic ? `${automatic.effective_settings.workers} workers · ${automatic.effective_settings.build_jobs_per_cell} build jobs` : 'Waiting for API'}</strong><small>{automatic ? `CPU bound ${automatic.bounds.cpu_workers} · RAM bound ${automatic.bounds.memory_workers} · max ${automatic.bounds.maximum_workers}` : 'physical, SMT and RAM bounds are separate'}</small></article>
      <article><span>ACTIVE QUEUE MODE</span><strong>{activeProfile?.id ?? 'unbound'}</strong><small>{activeMode} · lease cap {snapshot?.max_workers ?? '—'}</small></article>
    </div>
    <div className="performance-detection-detail">
      <article><span>DETECTION SOURCES</span><strong>{host?.capacity ? Object.values(host.capacity.sources).join(' · ') : 'Waiting for capability scan'}</strong><small>affinity {host?.capacity.cpu_affinity_limited ? 'limited' : 'not limited'} · cgroup CPU {host?.capacity.cgroup_cpu_quota ?? 'unlimited'} · cgroup RAM {host?.capacity.cgroup_memory_limit_mib ? `${host.capacity.cgroup_memory_limit_mib.toLocaleString()} MiB` : 'unlimited'}</small></article>
      <article><span>AUTO SELECTOR POLICY</span><strong>{automatic?.selector_version ?? '—'}</strong><small>{automatic ? `physical weight ${automatic.policy.physical_core_weight} · SMT weight ${automatic.policy.smt_sibling_weight} · reserve ${automatic.bounds.memory_reserve_mib.toLocaleString()} MiB · worker budget ${automatic.bounds.per_worker_budget_mib.toLocaleString()} MiB` : 'waiting for resolution'}</small></article>
      <article><span>CONFIGURATION AUTHORITIES</span><strong>{catalog.authority_path}</strong><small>active binding and lease cap: plans/priority-queue.toml · runtime settings are frozen into ledger evidence</small></article>
    </div>
    {linked && <div className="performance-detection-detail">
      <article><span>LINKED REFERENCE PRODUCERS</span><strong>{linkedProfile ? `${linkedProfile.workers} workers · ${linkedProfile.jvm_max_heap_mib.toLocaleString()} MiB heap ceiling` : 'BLOCKED'}</strong><small>{linkedProfile ? `${linkedProfile.id} · ${linkedProfile.qualification} · ${linkedProfile.jvm_active_processors} processors/JVM` : linked.blockers.join(' · ')}</small></article>
      <article><span>LINKED CAPACITY LADDER</span><strong>{linked.profiles.map(profile => `${profile.workers}${profile.eligible ? '✓' : '×'}`).join(' · ')}</strong><small>6 / 8 / 10 / 12 are separate TOML profiles; experimental profiles never auto-select</small></article>
      <article><span>LINKED AUTHORITY</span><strong>{linked.authority_path}</strong><small>{linkedProfile?.guidance ?? 'No reviewed profile currently fits detected resources'}</small></article>
    </div>}
    <div className="performance-override-ledger">
      <header><span>Setting</span><span>Detected auto</span><span>Active TOML</span><span>Resolution</span></header>
      {settingRows.map(row => <article key={row.name}><div><strong>{row.label}</strong><small>{row.name}</small></div><code>{displaySetting(row.name, row.automaticValue)}</code><code>{displaySetting(row.name, row.activeValue)}</code><span className={`evidence-badge ${row.tone}`}>{row.state}</span></article>)}
      {!settingRows.length && <div className="empty-state compact"><span>◇</span><strong>Waiting for automatic resolution</strong><p>The comparison appears after the read-only host scan completes.</p></div>}
    </div>
    <div className="performance-profile-tabs">{catalog.profiles.map(profile => <button key={profile.id} className={profile.id === selected.id ? 'active' : ''} onClick={() => setSelectedId(profile.id)}><strong>{profile.label}</strong><small>{profile.settings.worker_mode === 'automatic' ? 'auto workers' : `${profile.settings.workers} workers`} · {profile.host.memory_mib ? `${Math.round(profile.host.memory_mib / 1024)} GiB` : 'portable'}</small></button>)}</div>
    <div className="performance-profile-detail"><header><div><span className={`evidence-badge ${qualificationTone}`}>{selected.qualification.replaceAll('-', ' ')}</span><h4>{selected.label}</h4><p>{selected.description}</p></div><button onClick={() => void copyCommand()}>{copied ? 'Copied' : 'Copy preview command'}</button></header><div><article><span>CELL WORKERS</span><strong>{effective?.workers ?? 'AUTO'}</strong><small>{selected.id === 'auto' ? 'resolved now; frozen into run evidence' : 'independent long-lived JVM processes'}</small></article><article><span>BUILD JOBS / CELL</span><strong>{effective?.build_jobs_per_cell ?? selected.settings.build_jobs_per_cell}</strong><small>nested compiler parallelism</small></article><article><span>JVM HEAP CEILING</span><strong>{effective?.ghidra_heap_mib ? `${effective.ghidra_heap_mib} MiB` : 'ERGONOMIC'}</strong><small>maximum, not reserved allocation</small></article><article><span>GHIDRA CORE LIMIT</span><strong>{effective?.ghidra_core_limit ?? 'HOST'}</strong><small>per embedded JVM</small></article></div><footer><p>{selected.guidance}</p><code>{command}</code>{selected.evidence_path && <small>{selected.evidence_path}</small>}</footer></div>
  </section>;
}

function HashAnalysisBackendPanel({ factory }: { factory: FactoryApiState }) {
  const backend = factory.hashAnalysisBackend;
  const [message, setMessage] = useState('');
  if (!backend) return <section className="panel"><div className="empty-state compact"><span>◇</span><strong>Hash backend unavailable</strong><p>Reconnect the local API to read performance/hash-analysis.toml.</p></div></section>;
  const qualification = backend.gpu.qualification;
  const performance = qualification?.performance;
  const speedup = typeof performance?.probe_speedup === 'number'
    ? `${performance.probe_speedup.toFixed(2)}×`
    : '—';
  const setMode = async (mode: 'auto' | 'cpu' | 'gpu') => {
    setMessage(`Saving ${mode} mode…`);
    try {
      const result = await factory.setHashAnalysisMode(mode);
      setMessage(`${result.requested_mode.toUpperCase()} → ${result.effective_backend.device.toUpperCase()} · ${result.effective_backend.id}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Backend setting failed.');
    }
  };
  return <section className="panel hash-backend-panel">
    <header><div><span>HASH LOOKUP BACKEND</span><h3>{backend.effective_backend.id}</h3></div><code>{backend.performance.authority_path}</code></header>
    <div className="hash-backend-metrics">
      <article><span>DETECTED</span><strong>{backend.gpu.runtime_available ? 'WGPU + GPU' : 'CPU'}</strong><small>{backend.gpu.detected_devices.map(device => `${device.name} ${device.vendor_id}:${device.device_id}`).join(' · ') || 'no DRM GPU exposed'}</small></article>
      <article><span>REQUESTED → EFFECTIVE</span><strong>{backend.requested_mode.toUpperCase()} → {backend.effective_backend.device.toUpperCase()}</strong><small>{backend.fallback_reason ?? 'no fallback'}</small></article>
      <article><span>QUALIFICATION</span><strong>{backend.gpu.authoritative ? '0 MISMATCHES' : (qualification?.state ?? 'UNQUALIFIED').toUpperCase()}</strong><small>{qualification?.report_path ?? 'no qualification receipt'}</small></article>
      <article><span>PACKED LOOKUP</span><strong>{speedup}</strong><small>3,025,703 C10 queries · GPU probe versus CPU packed probe</small></article>
      <article><span>SCOPE</span><strong>EXACT LOOKUP</strong><small>{backend.effective_backend.scope.replaceAll('-', ' ')}</small></article>
    </div>
    <div className="hash-backend-controls"><div>{(['auto', 'gpu', 'cpu'] as const).map(mode => <button key={mode} className={backend.requested_mode === mode ? 'active' : ''} onClick={() => void setMode(mode)} disabled={factory.busyAction !== null}>{mode.toUpperCase()}</button>)}</div><p>{message || 'AUTO uses the qualified GPU lookup when available. CPU is the fail-safe fallback. Backend comparison runs only during explicit qualification.'}</p></div>
    <p className="hash-backend-boundary"><strong>GPU boundary:</strong> exact comparison of completed hash records only. Compilation, linking, binary construction, Ghidra analysis and FID generation always stay on the canonical CPU/toolchain path.</p>
  </section>;
}

function FidMatchingBackendPanel({ factory }: { factory: FactoryApiState }) {
  const backend = factory.fidMatchingBackend;
  const [message, setMessage] = useState('');
  if (!backend) return <section className="panel"><div className="empty-state compact"><span>◇</span><strong>FID scoring backend unavailable</strong><p>Reconnect the local API to read performance/fid-matching.toml.</p></div></section>;
  const qualification = backend.gpu.qualification;
  const setMode = async (mode: 'auto' | 'cpu' | 'gpu') => {
    setMessage(`Saving ${mode} mode…`);
    try {
      const result = await factory.setFidMatchingMode(mode);
      setMessage(`${result.requested_mode.toUpperCase()} → ${result.effective_backend.device.toUpperCase()} · ${result.effective_backend.id}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'FID scoring backend setting failed.');
    }
  };
  return <section className="panel hash-backend-panel">
    <header><div><span>FID CANDIDATE SCORER</span><h3>{backend.effective_backend.id}</h3></div><code>{backend.performance.authority_path}</code></header>
    <div className="hash-backend-metrics">
      <article><span>DETECTED</span><strong>{backend.gpu.runtime_available ? 'WGPU + GPU' : 'CPU'}</strong><small>{backend.gpu.detected_devices.map(device => `${device.name} ${device.vendor_id}:${device.device_id}`).join(' · ') || 'no DRM GPU exposed'}</small></article>
      <article><span>REQUESTED → EFFECTIVE</span><strong>{backend.requested_mode.toUpperCase()} → {backend.effective_backend.device.toUpperCase()}</strong><small>{backend.fallback_reason ?? 'no fallback'}</small></article>
      <article><span>NATIVE ORACLE CANARY</span><strong>{backend.gpu.authoritative ? '0 MISMATCHES' : qualification.state.toUpperCase()}</strong><small>{qualification.backend.effective?.join(' · ') ?? 'no effective backend evidence'} · {((qualification.truth_coverage ?? 0) * 100).toFixed(1)}% truth coverage</small></article>
      <article><span>GPU CHUNK</span><strong>{backend.performance.candidate_chunk_rows.toLocaleString()}</strong><small>{backend.performance.workgroup_size} threads/workgroup · bounded SQLite stream</small></article>
      <article><span>GPU WORK</span><strong>FID SCORING</strong><small>candidate scores + equal-highest winner selection</small></article>
    </div>
    <div className="hash-backend-controls"><div>{(['auto', 'gpu', 'cpu'] as const).map(mode => <button key={mode} className={backend.requested_mode === mode ? 'active' : ''} onClick={() => void setMode(mode)} disabled={factory.busyAction !== null}>{mode.toUpperCase()}</button>)}</div><p>{message || `${qualification.decision_mismatches ?? '—'} oracle mismatches · ${qualification.backend.fallback_cases?.length ?? 0} canary fallbacks`}</p></div>
    <p className="hash-backend-boundary"><strong>CPU boundary:</strong> compilation · linking · binary construction · Ghidra analysis · FID generation · query relationship export. <strong>GPU boundary:</strong> FID candidate scoring and winner selection only.</p>
  </section>;
}

function AttemptTimingRow({ attempt, now }: { attempt: CoordinatorAttempt; now: number }) {
  return <div><span className={`timing-result ${attempt.state}`}>{attempt.attempt_number > 1 ? `retry ${attempt.attempt_number}` : attempt.state}</span><p><strong>{attempt.job_id.slice(0, 12)}</strong><small>{attempt.worker_id} · {formatStartedAt(attempt.started_at)}{attempt.queue_wait_duration_ns !== undefined && attempt.queue_wait_duration_ns !== null ? ` · waited ${formatDurationNs(attempt.queue_wait_duration_ns)}` : ''}</small></p><b>{formatDurationNs(elapsedNs(attempt.started_at, now, attempt.ended_at))}</b></div>;
}

function CohortValidationLifecyclePanel({ lifecycle }: { lifecycle: CohortValidationLifecycle }) {
  const active = lifecycle.active_cohort;
  const performance = lifecycle.performance;
  return <section className="panel cohort-lifecycle-panel">
    <header><div><span>INTEGRATED VALIDATION</span><h3>{lifecycle.label}</h3></div><span className="operational-state blocked">PLANNED · DISARMED</span></header>
    <div className="cohort-lifecycle-facts">
      <article><span>SCIENTIFIC BLOCK</span><strong>10 libraries</strong><small>short scheduler blocks may resume</small></article>
      <article><span>GHIDRA / COHORT</span><strong>{lifecycle.summary.legacy_analyses_per_full_cohort} → {lifecycle.summary.fused_analyses_per_full_cohort}</strong><small>{lifecycle.summary.fused_analyses_per_full_cohort} duplicate analyses avoided</small></article>
      <article><span>PROJECTED CYCLE</span><strong>{performance.projected_fused_cycle_wall_hours_lower.toFixed(1)}–{performance.projected_fused_cycle_wall_hours_upper.toFixed(1)} h</strong><small>{performance.estimate_class.replaceAll('-', ' ')}</small></article>
      <article><span>COMPARISONS</span><strong>50/50 + corpus</strong><small>fold matrix · incremental noise view</small></article>
      <article><span>ADMISSION</span><strong>Manual review</strong><small>validation + discrimination + retention</small></article>
      <article><span>C80 PROGRAMME</span><strong>{lifecycle.summary.programme_cohorts} cohorts</strong><small>{lifecycle.summary.planned_validation_composites.toLocaleString()} validation composites</small></article>
    </div>
    <div className="cohort-lifecycle-chain">
      {lifecycle.stages.map((stage, index) => <Fragment key={stage.id}><span><b>{String(index + 1).padStart(2, '0')}</b><strong>{stage.label}</strong></span>{index < lifecycle.stages.length - 1 && <i>→</i>}</Fragment>)}
    </div>
    {active && <div className="cohort-lifecycle-active"><span>CURRENT RETROFIT</span><strong>{active.id}</strong><small>{active.libraries} libraries</small><em>WIDTH {active.width_state.replaceAll('-', ' ')}</em><em>VALIDATION {active.validation_state.replaceAll('-', ' ')}</em><em>ADMISSION {active.admission_state.replaceAll('-', ' ')}</em></div>}
    <div className="cohort-lifecycle-bound">
      {lifecycle.bound_cohorts.map(cohort => <article key={cohort.id}><b>{String(cohort.order).padStart(2, '0')}</b><p><strong>{cohort.id}</strong><small>{cohort.source_ids.join(' · ')}</small></p><span>{cohort.width_batch_state.replaceAll('-', ' ')}</span><span>{cohort.validation_state.replaceAll('-', ' ')}</span><em>AUTO MATERIALIZE + SCHEDULE</em></article>)}
    </div>
    <footer><code>{lifecycle.authority_path}</code><span>{lifecycle.query_evidence_contract} · routine Ghidra backfill {lifecycle.fusion.routine_backfill}</span></footer>
  </section>;
}

function CampaignProgrammePanel({ programme, lifecycle }: { programme: CampaignProgramme; lifecycle?: CohortValidationProgramme }) {
  const summary = programme.summary;
  const stageLabel = (stage: string) => stage.replaceAll('-', ' ').toUpperCase();
  const stageTone = (stage: string) => stage === 'queue-candidate'
    ? 'ready'
    : stage === 'candidate-screen'
      ? 'cold'
      : 'warning';
  const funnel = [
    ['Research frontier', summary.candidate_population, 'published candidates'],
    ['Source resolved', summary.research_source_pinned_candidates, 'registry-locked archives'],
    ['Archive cached', summary.research_source_cached_candidates, 'receipt-verified bytes'],
    ['C screen', summary.screened_candidates, 'accepted subjects'],
    ['Build source', summary.source_cached_candidates, 'promoted archives'],
    ['Recipe', summary.recipe_ready_candidates, 'reviewed adapters'],
    ['Qualification', summary.qualification_satisfied_candidates, 'sealed subjects'],
  ] as const;
  return <section className="panel c80-programme-panel">
    <div className="c80-programme-head"><div><span>C80 PROGRAMME · FOUR-SOURCE N80</span><h3>{programme.label}</h3></div><div><strong>{programme.candidate_cumulative_proxy_pct.toFixed(6)}%</strong><small>cumulative popularity proxy</small></div><div><strong>{summary.cohorts}</strong><small>10-wide cohorts · final {summary.final_cohort_size}</small></div><div><strong>{summary.planned_campaign_executions.toLocaleString()}</strong><small>planned width executions</small></div><span className="operational-state blocked">RESEARCH PROXY · DISARMED</span></div>
    <div className="c80-funnel" aria-label="C80 planning funnel">
      {funnel.map(([label, value, detail], index) => <Fragment key={label}><article><span>{label}</span><strong>{value.toLocaleString()}<small> / {summary.candidate_population}</small></strong><em>{detail}</em></article>{index < funnel.length - 1 && <i>→</i>}</Fragment>)}
    </div>
    <div className="c80-workload-strip"><span><b>{programme.route_profiles_per_library}</b> routes</span><span><b>{programme.treatments_per_route}</b> treatments</span><span><b>{programme.campaign_executions_per_library}</b> cells / accepted library</span><span><b>{programme.qualification_routes_per_library}</b> qualification edges / library</span><span><b>{summary.planned_qualification_cells.toLocaleString()}</b> maximum qualification cells</span></div>
    <div className="c80-cohort-ledger">
      <header><span>Cohort / research ranks</span><span>Research archive</span><span>Screened</span><span>Build source</span><span>Recipes</span><span>Qualification</span><span>Validation</span><span>Admission</span><span>Current gate</span><span></span></header>
      {programme.cohorts.map(cohort => {
        const lifecycleCohort = lifecycle?.cohorts.find(row => row.id === cohort.id);
        const validationStage = lifecycleCohort?.stages.find(stage => stage.id === 'validation-composites');
        const admissionStage = lifecycleCohort?.stages.find(stage => stage.id === 'corpus-admission');
        return <details key={cohort.id}>
          <summary><div><strong>{String(cohort.order).padStart(2, '0')} · {cohort.id}</strong><small>ranks {cohort.candidate_rank_start}–{cohort.candidate_rank_end} · {cohort.candidates.slice(0, 3).map(row => row.display_name).join(', ')}{cohort.capacity > 3 ? '…' : ''}</small></div><b>{cohort.counts.research_source_pinned}/{cohort.counts.research_source_cached}</b><b>{cohort.counts.screened}/{cohort.capacity}</b><b>{cohort.counts.source_pinned}/{cohort.counts.source_cached}</b><b>{cohort.counts.recipe_ready}/{cohort.capacity}</b><b>{cohort.counts.qualification_satisfied}/{cohort.capacity}</b><b className="lifecycle-state">{validationStage?.state.replaceAll('-', ' ') ?? 'unbound'}</b><b className="lifecycle-state">{admissionStage?.state.replaceAll('-', ' ') ?? 'unbound'}</b><span className={`evidence-badge ${stageTone(cohort.stage)}`}>{stageLabel(cohort.stage)}</span><em>EXPAND</em></summary>
          <section>{lifecycleCohort && <div className="c80-validation-chain">{lifecycleCohort.stages.slice(2).map(stage => <span key={stage.id}><strong>{stage.label}</strong><small>{stage.state.replaceAll('-', ' ')} · {stage.detail}</small></span>)}</div>}<header><span>Rank / candidate</span><span>Research archive</span><span>C screen</span><span>Build source</span><span>Recipe</span><span>Qualification</span><span>Next gate</span></header>{cohort.candidates.map(candidate => <article key={candidate.rank}><div><b>#{candidate.rank} {candidate.display_name}</b><small>{candidate.subject_id !== candidate.canonical_key ? `${candidate.canonical_key} → ${candidate.subject_id}` : candidate.canonical_key}</small></div><span className={candidate.research_source_cached ? 'pass' : 'pending'}>{candidate.research_source_cached ? 'CACHED' : candidate.research_source_pinned ? 'PINNED' : 'UNRESOLVED'}<br /><small>{candidate.research_source_resolver ?? candidate.research_source_reason}</small></span><span className={candidate.screened ? 'pass' : 'pending'}>{candidate.screened ? 'SCREENED' : 'REQUIRED'}</span><span className={candidate.source_cached ? 'pass' : 'pending'}>{candidate.source_cached ? 'VERIFIED' : candidate.source_pinned ? 'PINNED' : 'NOT PROMOTED'}</span><span className={candidate.recipe_ready ? 'pass' : 'pending'}>{candidate.recipe_ready ? 'REVIEWED' : 'REQUIRED'}</span><span className={candidate.qualification_satisfied ? 'pass' : 'pending'}>{candidate.qualification_satisfied ? candidate.qualification_state.toUpperCase() : candidate.width_batch_bound ? candidate.qualification_state.toUpperCase() : 'NOT DEFINED'}</span><strong>{stageLabel(candidate.stage)}</strong></article>)}</section>
        </details>;
      })}
    </div>
    <footer><code>{programme.authorities.source_lock}</code><span>Research archive cache ≠ accepted C-library cohort. Screening, recipe review and qualification remain independent gates.</span></footer>
  </section>;
}

function QualificationPipelinePanel({ factory }: { factory: FactoryApiState }) {
  const pipeline = factory.authority?.qualification_pipeline;
  if (!pipeline) return null;
  return <section className="panel qualification-pipeline-panel">
    <div className="panel-header"><h3>Campaign qualification pipeline</h3><span className={`evidence-badge ${pipeline.summary.blocked ? 'warning' : 'ready'}`}>{pipeline.state.toUpperCase()} · {pipeline.summary.satisfied}/{pipeline.summary.batches} GATES</span></div>
    <div className="qualification-chain" aria-label="Campaign qualification stages"><span><b>01</b><strong>Resolve</strong><small>all exact cells</small></span><i>→</i><span><b>02</b><strong>Compile qualify</strong><small>target + generation edges</small></span><i>→</i><span><b>03</b><strong>Seal</strong><small>input-bound evidence</small></span><i>→</i><span><b>04</b><strong>Build queue</strong><small>short chunks, disarmed</small></span><i>→</i><span><b>05</b><strong>Full-path canary</strong><small>compile + Ghidra + publish</small></span><i>→</i><span><b>06</b><strong>Admit</strong><small>explicit operator arm</small></span></div>
    <div className="qualification-gate-ledger">
      <header><span>Width batch</span><span>Compilation coverage</span><span>Authority / evidence</span><span>Promotion</span></header>
      {pipeline.gates.map(gate => <article key={gate.batch_id}><div><strong>{gate.batch_id}</strong><small>{gate.state.replaceAll('-', ' ')}</small></div><div><strong>{gate.summary.total ? `${gate.summary.built}/${gate.summary.total}` : 'legacy'}</strong><small>{gate.summary.failed} failed · {gate.summary.remaining} remaining</small></div><div><code>{gate.authority_path ?? 'historical digest exemption'}</code><small>{gate.evidence_path ?? gate.reason ?? 'no qualification evidence'}</small></div><span className={`evidence-badge ${gate.satisfied ? 'ready' : 'warning'}`}>{gate.satisfied ? gate.promotion_state.replaceAll('-', ' ') : 'blocked'}</span></article>)}
    </div>
    <footer><code>fidb-poc qualification status --project-root .</code><span>Passing qualification unlocks the auto-batch queue builder; the generated campaign remains disarmed until the canary and explicit operator admission.</span></footer>
  </section>;
}

function TimeBlockPlanPanel({ factory }: { factory: FactoryApiState }) {
  const plan = factory.authority?.time_block_plan;
  if (!plan) return null;
  const materialized = factory.authority?.materialized_campaigns.find(campaign => campaign.id === plan.id);
  const materializedBlocks = new Map(materialized?.blocks.map(block => [block.id, block]));
  const schedule = factory.preflight?.policy.schedule;
  const start = typeof schedule?.start === 'string' ? schedule.start : plan.blocks[0]?.expected_start_local ?? '01:00';
  const stop = typeof schedule?.stop_claiming === 'string' ? schedule.stop_claiming : '05:30';
  const finishStarted = schedule?.finish_started_batch === true;
  const chainBatches = schedule?.chain_batches === true;
  const active = factory.snapshot?.execution_block;
  const materializedReady = materialized?.readiness.ready === true;
  const candidate = factory.authority?.auto_batch_campaigns[0];
  return <section className="panel time-block-panel">
    <div className="panel-header"><h3>Time-aware campaign · {plan.label}</h3><span className="authority-badge">{materializedReady ? materialized?.state.replaceAll('-', ' ').toUpperCase() : 'DRAFT · DISARMED'}</span></div>
    <div className="time-block-summary">
      <article><span>NOMINAL WALL TIME</span><strong>{plan.summary.estimated_hours.toFixed(1)} h</strong><small>{plan.summary.planning_lower_hours.toFixed(1)}–{plan.summary.planning_upper_hours.toFixed(1)} h planning range</small></article>
      <article><span>BLOCKS</span><strong>{plan.summary.blocks}</strong><small>target {plan.policy.target_block_hours.toFixed(1)} h · hard planning ceiling {plan.policy.max_block_hours.toFixed(0)} h</small></article>
      <article><span>EXACT WIDTH</span><strong>{plan.summary.executions.toLocaleString()}</strong><small>{plan.summary.android_executions.toLocaleString()} Android executions included</small></article>
      <article><span>MEASURED BASIS</span><strong>{plan.reference.estimated_cells_per_wall_hour.toFixed(1)} cells/h</strong><small>{plan.performance_profile.label} · {plan.reference.case_id}</small></article>
    </div>
    <div className="time-block-schedule"><div><span>AUTOMATIC ADMISSION</span><strong>{start}–{stop} · Europe/Luxembourg</strong><small>{chainBatches ? 'Drained chunks chain while the window remains open.' : 'At most one ordered block starts per window.'} {finishStarted ? 'A started block drains completely after the window closes.' : 'Finish-started policy is not active.'}</small></div><div><span>CURRENT ADMISSION</span><strong>{active?.active ? active.batch_id : 'No block active'}</strong><small>{active?.active ? `${active.remaining ?? '—'} jobs remain · ${active.admission_id}` : 'No block is currently admitted'}</small></div><div><span>MANUAL TIMER BYPASS</span><code>fidb-poc queue start-block --project-root .</code><small>Requires an armed queue; admits one block but executes nothing itself.</small></div></div>
    {candidate && <>
      <div className="time-block-summary">
        <article><span>AUTO-BUILT CHUNKS</span><strong>{candidate.summary.chunks}</strong><small>{candidate.policy.target_minutes} min target · {candidate.policy.max_minutes} min central ceiling</small></article>
        <article><span>EXACT PARTITION</span><strong>{candidate.summary.executions.toLocaleString()}</strong><small>{candidate.summary.route_bundles} library/route bundles · all treatments kept together</small></article>
        <article><span>MANUAL FIT</span><strong>{Math.max(...candidate.chunks.map(chunk => chunk.planning_upper_minutes)).toFixed(0)} min</strong><small>worst +{Math.round(candidate.policy.uncertainty_fraction * 100)}% planning bound · final tail {candidate.chunks.at(-1)?.estimated_minutes.toFixed(0)} min</small></article>
        <article><span>CANDIDATE QUEUE</span><strong>{candidate.queue_integrity.replaceAll('-', ' ')}</strong><small>{candidate.queue} · never substituted into the live ledger</small></article>
      </div>
      <div className="time-block-ledger">
        <header><span>Candidate chunk</span><span>Libraries</span><span>Width</span><span>Estimate / range</span><span>State</span></header>
        {candidate.chunks.map(chunk => <article key={chunk.id}><div><strong>#{String(chunk.position).padStart(3, '0')}</strong><small>{chunk.id}</small></div><div><strong>{chunk.source_ids.join(' + ')}</strong><small>{chunk.plan}</small></div><div><strong>{chunk.executions.toLocaleString()} executions</strong><small>{chunk.route_ids.length} route bundles · all treatments</small></div><div><strong>{chunk.estimated_minutes.toFixed(1)} min</strong><small>{chunk.planning_lower_minutes.toFixed(1)}–{chunk.planning_upper_minutes.toFixed(1)} min</small></div><span className={`evidence-badge ${chunk.plan_integrity === 'verified' && chunk.queue_registered ? 'ready' : 'cold'}`}>{chunk.plan_integrity} · {chunk.queue_registered ? 'registered' : 'drifted'}</span></article>)}
      </div>
    </>}
    <div className="time-block-ledger">
      <header><span>Block / nominal window</span><span>Libraries</span><span>Width</span><span>Estimate / range</span><span>State</span></header>
      {plan.blocks.map(block => {
        const frozen = materializedBlocks.get(block.id);
        return <article key={block.id}><div><strong>#{String(block.position).padStart(2, '0')} · {start} → {block.expected_nominal_end_local}</strong><small>{block.id}</small></div><div><strong>{block.items.map(item => item.label).join(' + ')}</strong><small>{block.items.map(item => `${item.source_id}@${item.version}`).join(' · ')}</small></div><div><strong>{block.executions.toLocaleString()} executions</strong><small>{block.android_executions.toLocaleString()} Android · exact applicability</small></div><div><strong>{block.estimated_hours.toFixed(2)} h</strong><small>{block.planning_lower_hours.toFixed(2)}–{block.planning_upper_hours.toFixed(2)} h · ±{Math.round(plan.policy.uncertainty_fraction * 100)}%</small></div><span className={`evidence-badge ${frozen?.plan_integrity === 'verified' && frozen.queue_registered ? 'ready' : 'cold'}`}>{frozen ? `${frozen.plan_integrity} · ${frozen.queue_registered ? 'queued' : 'unregistered'}` : block.state.replaceAll('-', ' ')}</span></article>;
      })}
    </div>
    <footer className="time-block-note"><strong>{materializedReady ? 'Frozen cells, disarmed execution.' : 'Dynamic draft, stable execution.'}</strong><span>{materializedReady ? 'All five generated plans match their file pins and ordered queue-cell digests. The queue is registered but remains disarmed pending explicit operator review.' : 'Factor, compiler, route, treatment, source-size or performance-profile changes automatically update this projection. Materialization must freeze the block membership and plan digest first, so an armed campaign can never reshape itself silently.'}</span><code>{materialized?.materialization_digest ?? plan.plan_digest}</code></footer>
  </section>;
}

function BatchesView({ onNewBatch, batchOrder, setBatchOrder, rows, live, factory }: { onNewBatch: () => void; batchOrder: string[]; setBatchOrder: React.Dispatch<React.SetStateAction<string[]>>; rows: BatchRow[]; live: boolean; factory: FactoryApiState }) {
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
    <ViewIntro kicker="BATCH OPERATIONS" title="Batches" action={<button className="primary-action" onClick={onNewBatch}>Open matrix draft</button>} />
    <QualificationPipelinePanel factory={factory} />
    <TimeBlockPlanPanel factory={factory} />
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

function ToolchainPackPanel({ plans, languageLabel, workers }: { plans: ToolchainProfilePlan[]; languageLabel: string; workers: CoordinatorWorker[] }) {
  const [selectedProfileId, setSelectedProfileId] = useState('c-compiler-width-v1');
  const [copiedAction, setCopiedAction] = useState<string | null>(null);
  const selected = plans.find(plan => plan.profile.id === selectedProfileId) ?? plans[0];

  const copyCommand = async (action: string, command: string) => {
    try {
      await navigator.clipboard.writeText(command);
      setCopiedAction(action);
      window.setTimeout(() => setCopiedAction(current => current === action ? null : current), 1500);
    } catch {
      setCopiedAction(null);
    }
  };

  if (!selected) return <section className="panel toolchain-pack-panel empty-pack-profile">
    <div className="panel-header"><h3>No {languageLabel} pack profile</h3><span className="plan-state">TOML REQUIRED</span></div>
    <div className="empty-state"><span>◇</span><strong>The pack model is language-scoped</strong><p>Add a reviewed profile under toolchains/profiles before this language inherits any downloads, routes, or size estimate.</p></div>
  </section>;

  const externalRoutes = selected.routes.filter(route => route.provisioning === 'external-worker');
  const localRoutes = selected.routes.filter(route => route.provisioning !== 'external-worker');
  const profileTone = selected.state === 'blocked' || selected.summary.broken_packs || selected.summary.broken_routes ? 'warning' : selected.state === 'qualified' ? 'ready' : 'cold';
  return <section className="panel toolchain-pack-panel">
    <div className="pack-panel-header">
      <h3>{selected.profile.label}</h3>
      <div className="pack-profile-tabs">{plans.map(plan => <button className={plan.profile.id === selected.profile.id ? 'active' : ''} key={plan.profile.id} onClick={() => setSelectedProfileId(plan.profile.id)}><strong>{plan.profile.label}</strong><small>{plan.summary.coverage_requirements} requirements · {plan.summary.routes} implementations · {plan.summary.packs} packs</small></button>)}</div>
    </div>
    <div className="pack-state-strip">
      <article><span>PROFILE STATE</span><strong className={profileTone}>{selected.state.replaceAll('-', ' ')}</strong><small>next: {selected.recommended_next_action.replaceAll('-', ' ')}</small></article>
      <article><span>TARGET REQUIREMENTS</span><strong>{selected.summary.coverage_requirements}</strong><small>{selected.summary.primary_routes} primary · {selected.summary.cross_build_routes} cross-build · {selected.summary.native_reference_routes} native reference</small></article>
      <article><span>VERIFIED CACHE</span><strong>{selected.summary.verified_cached_packs} / {selected.summary.packs}</strong><small>{formatBytes(selected.summary.cached_download_bytes)} already present</small></article>
      <article><span>SAFELY PREPARED</span><strong>{selected.summary.prepared_packs} / {selected.summary.packs}</strong><small>{selected.summary.missing_preparations} still require extraction</small></article>
      <article><span>ROUTES QUALIFIED</span><strong>{selected.summary.qualified_routes} / {selected.summary.downloadable_routes}</strong><small>{selected.summary.composed_routes} composed · {selected.summary.missing_qualifications} await probes</small></article>
      <article><span>DOWNLOAD REMAINING</span><strong>{formatBytes(selected.summary.remaining_download_bytes)}</strong><small>{formatBytes(selected.summary.download_bytes)} full compressed pack</small></article>
      <article><span>PREPARED PAYLOAD</span><strong>{formatBytes(selected.summary.installed_bytes_estimate)}</strong><small>{selected.summary.installed_size_evidence}</small></article>
      <article><span>HOST CONTRACT</span><strong className={selected.host.compatible ? 'ready' : 'warning'}>{selected.host.required_system} / {selected.host.required_architecture}</strong><small>detected {selected.host.detected_system} / {selected.host.detected_architecture}</small></article>
    </div>
    <div className="pack-command-grid">
      {selected.cli_examples.map(example => <article key={example.action}><span>{example.action.toUpperCase()}</span><code>{example.shell}</code><button onClick={() => void copyCommand(example.action, example.shell)}>{copiedAction === example.action ? 'Copied' : 'Copy command'}</button></article>)}
    </div>
    <div className="pack-ledger">
      <div className="pack-ledger-head"><span>Pack / target</span><span>Compiler composition</span><span>Download / installed estimate</span><span>Integrity + licence</span><span>State</span></div>
      {selected.packs.map(pack => {
        const tone = lifecycleTone(pack.preparation.state === 'prepared' ? 'prepared' : pack.preparation.state === 'broken' ? 'broken' : pack.state);
        const stateLabel = `${pack.state === 'verified-cached' ? 'cached' : pack.state} · ${pack.preparation.state}`;
        return <article key={pack.id}><div><strong>{pack.label}</strong><small>{pack.target_ids.join(' · ')}</small><code>{pack.id}</code></div><div><strong>{pack.compiler_family} {pack.compiler_version}</strong><small>{pack.linker_family} {pack.linker_version} · {pack.runtime} {pack.runtime_version.split('-')[0]}</small><code>{pack.compiler_driver}</code></div><div><strong>{formatBytes(pack.download_bytes)}</strong><small>→ {pack.size_evidence.startsWith('measured-') ? '' : '≈ '}{formatBytes(pack.installed_bytes_estimate)}</small><code>{pack.size_evidence}</code></div><div><strong>{pack.sha256.slice(0, 16)}…</strong><small>{pack.license_ids.join(' · ')}</small><code>SHA-256 pinned</code></div><span className={`evidence-badge ${tone}`}>{stateLabel}</span></article>;
      })}
    </div>
    {selected.inputs.length > 0 && <div className="external-route-ledger"><header><span>USER-SUPPLIED, PINNED INPUTS</span><p>These are part of the reproducibility contract but are privately bound and never redistributed by the project.</p></header>{selected.inputs.map(input => <article key={input.id}><div><strong>{input.label}</strong><small>{input.kind} · {input.target_ids.join(' · ')}</small></div><code>{input.required_metadata.join(' + ')}</code><span className={`evidence-badge ${lifecycleTone(input.binding.state)}`}>{input.binding.state.replaceAll('-', ' ')}</span></article>)}</div>}
    <div className="route-lifecycle-ledger"><header><span>ROUTE COMPOSITION + QUALIFICATION</span></header>{localRoutes.map(route => {
      const definition = route.qualification?.definition;
      const composition = route.qualification?.composition?.state;
      return <article key={route.id}><div><strong>{route.label}</strong><small>{route.target_triple} · {route.compiler_id} · {route.evidence_role}</small></div><code>{definition ? `${definition.tool_pack_id} · ${definition.version_contains} · ${definition.smoke_languages.join('+')}` : 'qualification authority unavailable'}</code><small>{composition ? `composition: ${composition}` : definition?.composition === 'none' ? 'direct prepared pack' : 'blocked by prerequisites'}</small><span className={`evidence-badge ${lifecycleTone(route.state)}`}>{route.state.replaceAll('-', ' ')}</span></article>;
    })}</div>
    {externalRoutes.length > 0 && <div className="external-route-ledger"><header><span>MANAGED EXTERNAL NATIVE ROUTES</span></header>{externalRoutes.map(route => {
      const liveWorker = workers.find(worker => worker.state === 'online' && worker.pools.includes(route.worker_class === 'macos-native-remote' ? 'macos-native' : route.worker_class));
      const defined = route.qualification_state === 'external-definition-reviewed';
      const state = liveWorker ? 'worker online' : defined ? 'definition ready · worker offline' : 'native definition required';
      const tone = liveWorker ? 'ready' : 'warning';
      return <article key={route.id}><div><strong>{route.label}</strong><small>{route.target_triple} · {route.worker_class}</small></div><code>{route.external_requirements.join(' + ')}</code><span className={`evidence-badge ${tone}`}>{state}</span></article>;
    })}</div>}
    <footer className="pack-trace"><div><span>PROFILE DIGEST</span><code>{selected.profile_digest}</code></div><div><span>AUTHORITY CHAIN</span><code>{selected.profile.authority_path} → routes.toml → inputs.toml + packs.toml → qualifications.toml</code></div><div><span>LIFECYCLE STORES</span><code>{selected.managed_downloads} → {selected.managed_prepared} → {selected.managed_composed} → {selected.managed_qualified}</code></div></footer>
  </section>;
}

function ToolchainsView({ factory, selectedLanguageId, setSelectedLanguageId }: { factory: FactoryApiState; selectedLanguageId: string; setSelectedLanguageId: React.Dispatch<React.SetStateAction<string>> }) {
  const inventory = factory.capabilities?.toolchains.entries ?? [];
  const targets = factory.authority?.targets ?? [];
  const laneRegistry = factory.authority?.lane_registry;
  const lanes = laneRegistry?.lanes ?? [];
  const sublaneCount = lanes.reduce((total, lane) => total + lane.sublanes.length, 0);
  const mappedSublaneCount = lanes.reduce((total, lane) => total + lane.sublanes.filter(sublane => sublane.definition_state === 'mapped').length, 0);
  const universe = factory.authority?.coverage_universe;
  const widthStudy = factory.authority?.width_studies.find(study => study.language_id === selectedLanguageId);
  const widthDefault = widthStudy?.presets.find(preset => preset.id === widthStudy.default_preset);
  const requirementByTarget = new Map((widthStudy?.toolchain_requirements ?? []).map(requirement => [requirement.target_id, requirement]));
  const selectedLanguage = universe?.languages.find(language => language.id === selectedLanguageId);
  const languageCompilerFamilies = (universe?.compiler_families ?? []).filter(family => family.language_ids.includes(selectedLanguageId));
  const languageProfiles = (universe?.profiles ?? []).filter(profile => profile.language_id === selectedLanguageId);
  const languageScenarios = (universe?.scenarios ?? []).filter(scenario => scenario.language_id === selectedLanguageId);
  const languagePackPlans = (factory.capabilities?.toolchain_profiles?.plans ?? []).filter(plan => plan.profile.language_id === selectedLanguageId);
  const languagePackRouteIds = new Set(languagePackPlans.flatMap(plan => plan.profile.route_ids));
  const packRoutes = (factory.authority?.toolchain_pack_catalog.routes ?? []).filter(route => languagePackRouteIds.has(route.id));
  const compilerWidthPlan = languagePackPlans.find(plan => plan.profile.id === 'c-compiler-width-v1');
  const compilerWidthIds = new Set((compilerWidthPlan?.routes ?? []).map(route => route.compiler_id));
  const compilerWidthRows = (factory.authority?.toolchain_pack_catalog.compilers ?? []).filter(compiler => compilerWidthIds.has(compiler.id));
  const plannedPackRouteById = new Map(languagePackPlans.flatMap(plan => plan.routes).map(route => [route.id, route]));
  const nativeRoutes = factory.capabilities?.native_routes ?? [];
  const [targetFilter, setTargetFilter] = useState<'all' | 'study' | 'ready' | 'not-installed' | 'unregistered'>('all');
  const [targetQuery, setTargetQuery] = useState('');
  const [expandedTargets, setExpandedTargets] = useState<Set<string>>(new Set());
  const capabilityById = new Map(inventory.map(row => [row.id, row]));
  const nativeById = new Map(nativeRoutes.map(row => [row.id, row]));
  const targetRows = targets.map(target => {
    const targetToolchains = target.toolchain_ids.flatMap(id => {
      const row = capabilityById.get(id);
      return row ? [row] : [];
    });
    const sourceToolchains = target.source_capable_toolchain_ids.flatMap(id => {
      const row = capabilityById.get(id);
      return row ? [row] : [];
    });
    const targetNativeRoutes = target.native_route_ids.flatMap(id => {
      const row = nativeById.get(id);
      return row ? [row] : [];
    });
    const targetPackRoutes = packRoutes.flatMap(route => {
      if (route.target_id !== target.id) return [];
      return [plannedPackRouteById.get(route.id) ?? { ...route, state: 'definition-required' }];
    });
    const nativeInstalled = targetNativeRoutes.some(route => route.ready);
    const sourceCached = sourceToolchains.some(toolchain => toolchain.state === 'verified-cached');
    const packQualified = targetPackRoutes.some(route => route.state === 'qualified');
    const cachedInputs = targetToolchains.filter(toolchain => toolchain.state === 'verified-cached').length + targetPackRoutes.filter(route => route.state === 'qualified').length;
    const state = nativeInstalled
      ? 'installed'
      : sourceCached || packQualified
        ? 'cached'
        : sourceToolchains.length || targetPackRoutes.length
          ? 'not-installed'
          : target.archive_capable_toolchain_ids.length
            ? 'archive-only'
            : 'unregistered';
    return { target, targetToolchains, sourceToolchains, targetNativeRoutes, targetPackRoutes, cachedInputs, state, packQualified, requirement: requirementByTarget.get(target.id) };
  });
  const normalizedQuery = targetQuery.trim().toLowerCase();
  const visibleTargets = targetRows.filter(row => {
    const matchesFilter = targetFilter === 'all'
      || (targetFilter === 'study' && Boolean(row.requirement))
      || (targetFilter === 'ready' && (row.state === 'installed' || row.state === 'cached'))
      || (targetFilter === 'not-installed' && (row.state === 'not-installed' || row.state === 'archive-only'))
      || (targetFilter === 'unregistered' && row.state === 'unregistered');
    const searchText = [row.target.id, row.target.label, row.target.platform, row.target.architecture, row.target.binary_format, row.requirement?.compiler_label, row.requirement?.wave, ...row.targetToolchains.map(toolchain => toolchain.id), ...row.targetPackRoutes.flatMap(route => [route.id, route.label, route.compiler_id, route.compiler_family, route.target_triple])].join(' ').toLowerCase();
    return matchesFilter && (!normalizedQuery || searchText.includes(normalizedQuery));
  });
  const readyTargets = targetRows.filter(row => row.state === 'installed' || row.state === 'cached').length;
  const sourceTargets = targetRows.filter(row => row.target.native_route_ids.length || row.target.source_capable_toolchain_ids.length || row.targetPackRoutes.length).length;
  const gapTargets = targetRows.length - sourceTargets;
  const campaignScenario = languageScenarios.find(row => row.id === 'c-campaign-b-four-source-n80');
  const laneInventory = factory.laneInventory;
  const laneSummary = laneInventory?.summary;
  const latestWidthRun = laneInventory?.latest_complete_width_run;
  const laneDatabases = laneInventory?.databases ?? [];
  const widthQualified = compilerWidthPlan?.summary.qualified_routes ?? 0;
  const widthRoutes = compilerWidthPlan?.summary.routes ?? 0;
  return <div className="view-stack">
    <ViewIntro kicker={`${selectedLanguage?.label.toUpperCase() ?? selectedLanguageId.toUpperCase()} COVERAGE POSSIBILITY SPACE`} title="Targets & toolchains" action={<button className="primary-action" onClick={() => void factory.refresh()} disabled={factory.connection === 'connecting'}>{factory.connection === 'live' ? 'Refresh' : 'Retry connection'}</button>} />
    {factory.error && <div className="toast warning" role="status">! {factory.error}</div>}

    <LanguageScopeSelector languages={universe?.languages ?? []} selectedId={selectedLanguageId} onSelect={setSelectedLanguageId} />

    <section className="panel lane-workflow-panel">
      <div className="panel-header"><h3>Database workflow</h3><span className="plan-state ready">READ-ONLY LIVE INVENTORY</span></div>
      <div className="lane-workflow-track">
        <article className={widthRoutes > 0 && widthQualified === widthRoutes ? 'complete' : 'pending'}><b>01</b><span>TOOLCHAIN WIDTH</span><strong>{widthQualified} / {widthRoutes || '—'}</strong><small>qualified executable routes</small></article><i>→</i>
        <article className={latestWidthRun ? 'complete' : 'pending'}><b>02</b><span>MEASURED EVIDENCE</span><strong>{latestWidthRun ? `${latestWidthRun.completed_executions}/${latestWidthRun.scheduled_executions}` : 'NONE'}</strong><small>{latestWidthRun ? `${latestWidthRun.fixed_recipe} · ${formatPlanningDurationNs(latestWidthRun.wall_time_ns)}` : 'complete one fixed-library width run'}</small></article><i>→</i>
        <article className={(laneSummary?.raw_generations ?? 0) > 0 ? 'complete' : latestWidthRun ? 'next' : 'blocked'}><b>03</b><span>RAW LANE GENERATIONS</span><strong>{laneSummary?.raw_generations ?? 0}</strong><small>{latestWidthRun ? 'next: compile selected broad lanes' : 'requires measured evidence'}</small></article><i>→</i>
        <article className={(laneSummary?.compact_generations ?? 0) > 0 ? 'complete' : 'held'}><b>04</b><span>COMPACT COPY</span><strong>{laneSummary?.compact_generations ?? 0}</strong><small>held as a separate explicit experiment</small></article><i>→</i>
        <article className="gated"><b>05</b><span>ECOLOGICAL VALIDATION</span><strong>GATE</strong><small>held-out binaries + false positives</small></article><i>→</i>
        <article className="blocked"><b>06</b><span>NATIVE PROJECTION</span><strong>{laneDatabases.reduce((total, row) => total + row.native_projections, 0)}</strong><small>relationship-complete evidence required</small></article><i>→</i>
        <article className={(laneSummary?.active_packs ?? 0) > 0 ? 'complete' : 'blocked'}><b>07</b><span>ACTIVE ANALYST PACKS</span><strong>{laneSummary?.active_packs ?? 0}</strong><small>none until every admission gate passes</small></article>
      </div>
      {latestWidthRun && <div className="latest-width-evidence"><span>Latest complete evidence</span><strong>{latestWidthRun.fixed_recipe}</strong><code>{latestWidthRun.run_id}</code><p>{latestWidthRun.successful_route_profile_pairs} route × treatment pairs · {latestWidthRun.signature_records.toLocaleString()} observations · {latestWidthRun.unique_signatures.toLocaleString()} unique signatures · {formatBytes(latestWidthRun.retained_bytes)} retained · {formatBytes(latestWidthRun.peak_scratch_bytes)} peak scratch</p><small>{latestWidthRun.path}</small></div>}
    </section>

    <section className="panel lane-model-panel">
      <div className="panel-header lane-model-header"><h3>Lane inventory · {laneRegistry?.schema_version ?? 'LOADING'}</h3><span className="plan-state">EXPERIMENTAL · {laneSummary?.active_packs ?? 0} ACTIVE PACKS</span></div>
      <div className="lane-summary-strip">
        <article><span>USER-VISIBLE LANES</span><strong>{laneRegistry ? lanes.length : '—'}</strong><small>install and selection boundary</small></article>
        <article><span>EXACT SUBLANES</span><strong>{laneRegistry ? sublaneCount : '—'}</strong><small>query-compatibility boundary</small></article>
        <article className="ready"><span>GHIDRA MAPPED</span><strong>{laneRegistry ? mappedSublaneCount : '—'}</strong><small>language + compiler spec defined</small></article>
        <article className="warn"><span>UNRESOLVED</span><strong>{laneRegistry ? sublaneCount - mappedSublaneCount : '—'}</strong><small>coverage intent, not admission</small></article>
        <article><span>RAW / COMPACT DBS</span><strong>{laneInventory ? `${laneSummary?.raw_generations} / ${laneSummary?.compact_generations}` : '—'}</strong><small>{formatBytes(laneSummary?.lane_database_bytes ?? 0)} managed evidence</small></article>
        <article><span>ACTIVE PACKS</span><strong>{laneInventory ? laneSummary?.active_packs : '—'}</strong><small>separate publication boundary</small></article>
      </div>
      <div className="lane-grid">{lanes.map(lane => {
        const mapped = lane.sublanes.filter(sublane => sublane.definition_state === 'mapped').length;
        const targetIds = new Set(lane.sublanes.map(sublane => sublane.target_id));
        const buildRoutes = [...plannedPackRouteById.values()].filter(route => targetIds.has(route.target_id));
        const qualifiedBuildRoutes = buildRoutes.filter(route => route.state === 'qualified').length;
        const databases = laneDatabases.filter(database => database.lane_id === lane.id);
        const raw = databases.filter(database => database.kind === 'raw').length;
        const compact = databases.filter(database => database.kind === 'compact').length;
        return <article className={`lane-card ${databases.length ? 'materialized' : ''}`} key={lane.id}>
          <header><div><strong>{lane.label}</strong><small>{lane.id} · {lane.platform} / {lane.architecture_family}</small></div><span className="lane-count">{mapped}/{lane.sublanes.length} mapped · {qualifiedBuildRoutes}/{buildRoutes.length} routes ready</span></header>
          <p>{lane.description}</p>
          <div className="lane-sublane-list">{lane.sublanes.map(sublane => <div key={sublane.id}><span className={`cap-dot ${sublane.definition_state === 'mapped' ? 'ready' : 'warning'}`} /><div><strong>{sublane.target.label}</strong><small>{sublane.id}</small></div><code>{sublane.target.bits}-bit · {sublane.target.endianness} · {sublane.target.binary_format}</code><b>{sublane.definition_state}</b></div>)}</div>
          <footer>One analyst pack · {lane.sublanes.length} internal selector{lane.sublanes.length === 1 ? '' : 's'} · {buildRoutes.length ? `${qualifiedBuildRoutes}/${buildRoutes.length} executable build routes` : 'no executable build route yet'} · {raw} raw / {compact} compact generations</footer>
        </article>;
      })}</div>
      {laneDatabases.length > 0 && <div className="lane-database-ledger"><header><span>DISCOVERED MANAGED DATABASES</span><span>GENERATION</span><span>EVIDENCE</span><span>STORAGE</span><span>ADMISSION</span></header>{laneDatabases.map(database => <article key={database.path}><div><strong>{database.lane_id}</strong><small>{database.path}</small></div><code>{database.generation_id}</code><span><b>{database.kind}</b><small>{database.raw_observations.toLocaleString()} occurrences{database.unique_signatures === null ? '' : ` · ${database.unique_signatures.toLocaleString()} unique`}</small></span><strong>{formatBytes(database.bytes)}</strong><span className={`evidence-badge ${database.active ? 'ready' : 'cold'}`}>{database.active ? 'active' : database.ecological_validation_state.replaceAll('-', ' ')}</span></article>)}</div>}
      {laneInventory && laneDatabases.length === 0 && <div className="lane-database-empty"><span>NEXT MATERIALIZATION STEP</span><p>No lane database exists under <code>{laneInventory.roots.lane_databases}</code>. The completed {latestWidthRun?.fixed_recipe ?? 'width'} evidence remains untouched and is ready for preview-first raw lane compilation. Deduplication stays held.</p><small>Inventory opens SQLite metadata read-only; refresh does not compute digests or run a full integrity scan.</small></div>}
      {(laneSummary?.issues ?? 0) > 0 && <div className="inline-warning">{laneSummary?.issues} managed inventory item{laneSummary?.issues === 1 ? '' : 's'} could not be inspected. Review the lane inventory API before using them.</div>}
      <div className="lane-experiment-note"><span>REVERSIBLE EXPERIMENT</span><code>{laneRegistry?.authority_path ?? 'lanes/registry.toml'}</code></div>
    </section>

    {widthStudy && widthDefault && <section className="panel toolchain-demand-summary"><h3>Acquisition demand · {widthStudy.id}</h3><div><article><span>ORDERED REQUIREMENTS</span><strong>{widthStudy.toolchain_requirements.length}</strong><small>target + reference compiler pairs</small></article><article><span>DEFAULT ACTIVE</span><strong>{widthDefault.routes}</strong><small>first N requirements</small></article><article className="ready"><span>HOST INSTALLED</span><strong>{widthStudy.toolchain_requirements.filter(row => row.route_state === 'installed').length}</strong><small>verified native routes</small></article><article className="remote"><span>LINUX CROSS ROUTES</span><strong>{languagePackPlans.find(plan => plan.profile.id === 'c-top10-linux')?.summary.cross_build_routes ?? 0}</strong><small>currently PE/COFF from Linux</small></article><article className="warn"><span>EXTERNAL NATIVE</span><strong>{widthStudy.toolchain_requirements.filter(row => row.route_state === 'remote-required').length}</strong><small>Apple worker + MSVC remain distinct</small></article></div></section>}

    <ToolchainPackPanel plans={languagePackPlans} languageLabel={selectedLanguage?.label ?? selectedLanguageId} workers={factory.snapshot?.workers ?? []} />

    {compilerWidthPlan && <section className="panel compiler-generation-panel">
      <div className="panel-header"><h3>Compiler width · {compilerWidthPlan.profile.id}</h3><span className="plan-state">{compilerWidthPlan.summary.qualified_routes} / {compilerWidthPlan.summary.routes} ROUTES QUALIFIED</span></div>
      <div className="compiler-generation-ledger">{compilerWidthRows.map(compiler => {
        const routes = compilerWidthPlan.routes.filter(route => route.compiler_id === compiler.id);
        const qualified = routes.filter(route => route.state === 'qualified').length;
        return <article key={compiler.id}><header><strong>{compiler.id}</strong><span className={`evidence-badge ${qualified === routes.length ? 'ready' : 'cold'}`}>{qualified}/{routes.length} ready</span></header><p>{compiler.family} · {compiler.version}</p><small>{new Set(routes.map(route => route.target_id)).size} target{routes.length === 1 ? '' : 's'} · {compiler.generation}</small><code>{routes.map(route => route.target_id).join(' · ')}</code></article>;
      })}</div>
      <footer><span>DEFERRED, STILL VISIBLE</span><p>{factory.authority?.toolchain_pack_catalog.compiler_width.selection.deferred_families.join(' · ')}</p></footer>
    </section>}

    <section className="panel coverage-universe-panel">
      <div className="panel-header"><h3>Population denominators · {universe?.schema_version ?? 'LOADING'}</h3><span className="authority-badge">{universe?.authority_path ?? 'coverage/universe.toml'}</span></div>
      <div className="coverage-population evidence-population">
        <div><span>FOUR-SOURCE N80</span><strong>{universe?.population.published_four_source_n80_families ?? '—'}</strong><small>published popularity-proxy head</small></div>
        <div className="primary"><span>CAMPAIGN-B HEAD</span><strong>{universe?.population.published_priority_head_families ?? '—'}</strong><small>N80 + {universe?.population.tier_zero_families ?? '—'} Tier-0 subjects</small></div>
        <div><span>NINE-SOURCE SPINE</span><strong>{universe?.population.nine_source_candidate_spine_keys.toLocaleString() ?? '—'}</strong><small>raw exact-key candidates</small></div>
        <div><span>SHARED FRONTIER</span><strong>{universe?.population.nine_source_shared_frontier_keys.toLocaleString() ?? '—'}</strong><small>supported by ≥2 source families</small></div>
        <div className="candidate"><span>NINE-SOURCE N80</span><strong>{universe?.population.nine_source_n80_candidate_rank.toLocaleString() ?? '—'}</strong><small>rank cutoff · pre-screen, not family count</small></div>
        <div className="provisional"><span>GLOBAL ESTIMATE</span><strong>{universe ? `${(universe.population.global_family_lower_estimate / 1_000_000).toFixed(1)}–${(universe.population.global_family_upper_estimate / 1_000_000).toFixed(1)}M` : '—'}</strong><small>provisional · central {(universe?.population.global_family_central_estimate ?? 0) / 1_000_000}M</small></div>
      </div>
      <div className="coverage-dimension-grid">{(universe?.dimensions ?? []).map((dimension, index) => <article key={dimension.id}><span>{String(index + 1).padStart(2, '0')} · {dimension.layer}</span><h4>{dimension.label}</h4><p>{dimension.description}</p><div>{dimension.facets.map(facet => <em key={facet}>{facet}</em>)}</div><footer><b>{dimension.matrix_role}</b><small>{dimension.matrix_role === 'analysis-reuse' ? 'can reuse compile artifacts' : dimension.matrix_role === 'bounded-profile' ? 'sample as named treatments' : dimension.matrix_role === 'applicability' ? 'route-filtered, never blindly multiplied' : dimension.matrix_role === 'multiplier' ? 'creates distinct binary identities' : 'changes interpretation or admission'}</small></footer></article>)}</div>
      {universe && <p className="coverage-caveat"><span>i</span>{universe.population.population_caveat}</p>}
    </section>

    {selectedLanguage && <section className="panel language-policy-panel"><div className="panel-header"><h3>{selectedLanguage.label} matrix contract</h3><span className={`language-state ${selectedLanguage.state}`}>{selectedLanguage.state.replaceAll('-', ' ')}</span></div><div className="language-policy-body"><article><span>COVERAGE DENOMINATOR</span><p>{selectedLanguage.denominator}</p><small>{selectedLanguage.caveat}</small><code>{selectedLanguage.authority}</code></article><article><span>LANGUAGE-OWNED TREATMENT AXES</span><div>{selectedLanguage.treatment_axes.map(axis => <em key={axis}>{axis}</em>)}</div></article></div></section>}

    <div className="coverage-planning-grid">
      <section className="panel compiler-family-panel">
        <div className="panel-header"><h3>Toolchain breadth · family × version × route</h3><span className="plan-state">{languageProfiles.length || 'NO'} CANDIDATE PROFILES</span></div>
        <div className="compiler-family-list">{languageCompilerFamilies.map(family => <article key={family.id}><header><div><strong>{family.label}</strong><small>{family.route_scope}</small></div><span className={`coverage-state ${family.state}`}>{family.state}</span></header><p>{family.version_strategy}</p><div>{family.settings.map(setting => <em key={setting}>{setting}</em>)}</div><footer>{languageProfiles.filter(profile => profile.compiler_family === family.id).length} candidate profiles · route-specific mapping required</footer></article>)}</div>
        {!languageCompilerFamilies.length && <div className="empty-state"><span>◇</span><strong>No toolchain family registered</strong><p>This language remains vocabulary-only until a reviewed finite policy is added.</p></div>}
        {languageProfiles.length ? <details className="calibration-pack"><summary>Inspect the illustrative language profile set <span>{languageProfiles.length}</span></summary><div>{languageProfiles.map((profile, index) => <article key={profile.id}><b>{String(index + 1).padStart(2, '0')}</b><div><strong>{profile.label}</strong><small>{profile.route_scope}</small></div><code>{profile.controls.join(' · ')}</code><span className={`scenario-evidence ${profile.evidence_class}`}>{profile.evidence_class}</span></article>)}</div></details> : <div className="profile-gap"><span>PROFILE QUALIFICATION REQUIRED</span><p>The treatment axes are visible above, but no numeric multiplier is asserted for {selectedLanguage?.label}.</p></div>}
      </section>
      <section className="panel scale-scenario-panel">
        <div className="panel-header"><h3>Matrix scale</h3><span className="plan-state ready">{campaignScenario ? `PROPOSED ${campaignScenario.unique_executions.toLocaleString()}` : 'DENOMINATOR PENDING'}</span></div>
        <div className="scenario-list">{languageScenarios.map(scenario => <article className={scenario.evidence_class} key={scenario.id}><header><div><span className={`scenario-evidence ${scenario.evidence_class}`}>{scenario.evidence_class}</span><strong>{scenario.label}</strong><small>{scenario.scope}</small></div><b>{scenario.unique_executions.toLocaleString()}</b></header><code>{scenario.library_families.toLocaleString()} families × {scenario.releases} releases × {scenario.routes} routes × {scenario.profiles} profiles</code><footer><span>{scenario.replayed_executions.toLocaleString()} executions with ×{scenario.replay_multiplier} replay</span><small>{scenario.caveat}</small><code>{scenario.authority}</code></footer></article>)}</div>
        {!languageScenarios.length && <div className="empty-state"><span>◇</span><strong>No numeric scenario asserted</strong><p>Screen the family denominator and qualify a finite {selectedLanguage?.label} profile policy before estimating executions.</p></div>}
      </section>
    </div>

    <section className="panel coverage-ledger-model"><div className="panel-header"><h3>Coverage state</h3><span className="authority-badge">SHARED ACROSS LANGUAGES</span></div><div>{[['01','Possible','candidate or unresolved'],['02','Catalogued','canonical identity'],['03','Executable','capability verified'],['04','Planned','frozen denominator'],['05','Built','sealed evidence'],['06','Admitted','QC + replay + collision gates'],['07','Detected','held-out or operational utility']].map(([order,label,note], index) => <Fragment key={label}><article><b>{order}</b><strong>{label}</strong><small>{note}</small></article>{index < 6 && <span>→</span>}</Fragment>)}</div></section>
    <div className="readiness-divider"><span>HOST READINESS</span></div>
    <section className="toolchain-summary">
      <article><span>CATALOGUED TARGET CONTEXTS</span><strong>{factory.authority ? targetRows.length : '—'}</strong><small>possible target / ISA / ABI rows</small></article><article><span>READY ON THIS HOST</span><strong>{factory.capabilities ? readyTargets : '—'}</strong><small>host-installed or checksum-cached source routes</small></article><article><span>REGISTERED SOURCE COVERAGE</span><strong>{factory.authority ? sourceTargets : '—'}</strong><small>native or reviewed cross compiler, installed or not</small></article><article className="warn"><span>CATALOGUED ROUTE GAP</span><strong>{factory.authority ? gapTargets : '—'}</strong><small>{inventory.length} pinned compiler/archive identities tracked separately</small></article>
    </section>
    <section className="panel data-panel">
      <div className="filterbar"><button className={targetFilter === 'all' ? 'filter active' : 'filter'} onClick={() => setTargetFilter('all')}>All <span>{targetRows.length}</span></button>{widthStudy && <button className={targetFilter === 'study' ? 'filter active' : 'filter'} onClick={() => setTargetFilter('study')}>Width study <span>{widthStudy.toolchain_requirements.length}</span></button>}<button className={targetFilter === 'ready' ? 'filter active' : 'filter'} onClick={() => setTargetFilter('ready')}>Installed / cached <span>{readyTargets}</span></button><button className={targetFilter === 'not-installed' ? 'filter active' : 'filter'} onClick={() => setTargetFilter('not-installed')}>Not installed <span>{targetRows.filter(row => row.state === 'not-installed' || row.state === 'archive-only').length}</span></button><button className={targetFilter === 'unregistered' ? 'filter active' : 'filter'} onClick={() => setTargetFilter('unregistered')}>No route <span>{targetRows.filter(row => row.state === 'unregistered').length}</span></button><label className="filter-search">⌕<input value={targetQuery} onChange={event => setTargetQuery(event.target.value)} placeholder="Search target or toolchain" aria-label="Search target or toolchain" /></label></div>
      <div className="target-inventory">
        {visibleTargets.map(row => {
          const tone = row.state === 'installed' || row.state === 'cached' ? 'ready' : row.state === 'unregistered' ? 'warning' : 'cold';
          const stateLabel = row.state === 'installed' ? 'HOST INSTALLED' : row.state === 'cached' ? row.packQualified ? 'QUALIFIED ROUTE READY' : 'PINNED CACHE READY' : row.state === 'not-installed' ? 'SOURCE ROUTE NOT QUALIFIED' : row.state === 'archive-only' ? 'ARCHIVE EXTRACTION ONLY' : 'NO REVIEWED ROUTE';
          return <details className="target-inventory-card" key={row.target.id} open={expandedTargets.has(row.target.id)} onToggle={event => {
            const isOpen = event.currentTarget.open;
            setExpandedTargets(current => {
              if (current.has(row.target.id) === isOpen) return current;
              const next = new Set(current);
              if (isOpen) next.add(row.target.id); else next.delete(row.target.id);
              return next;
            });
          }}>
            <summary><span className={`cap-dot ${tone}`} /><div><strong>{row.target.label}</strong><small>{row.target.id} · {row.target.catalog_state}{row.requirement ? ` · W${String(row.requirement.order).padStart(2, '0')} ${row.requirement.order <= (widthDefault?.routes ?? 0) ? 'ACTIVE' : 'LATER'}` : ''}</small></div><code>{row.target.bits}-bit · {row.target.endianness} · {row.target.binary_format}</code><span className={`evidence-badge ${tone}`}>{stateLabel}</span><p><b>{row.sourceToolchains.length + row.targetNativeRoutes.length + row.targetPackRoutes.length}</b><small>source routes</small></p><p><b>{row.target.archive_capable_toolchain_ids.length}</b><small>archive candidates</small></p><p><b>{row.cachedInputs}</b><small>cached identities</small></p><i>⌄</i></summary>
            <div className="target-detail">
              <div className="target-evidence"><span>AUTHORITY</span><code>{row.target.evidence.join(' · ')}</code><small>{row.target.catalog_state === 'study-observed' ? 'Observed in the sensitivity study; no build route has been reviewed.' : 'Target identity is catalogued independently of installation state.'}</small></div>
              {row.requirement && <div className="target-demand-row"><b>W{String(row.requirement.order).padStart(2, '0')}</b><p><strong>{row.requirement.compiler_label} · {row.requirement.wave}</strong><small>{row.requirement.rationale}</small></p><code>{row.requirement.version_policy}</code><span className={`route-requirement-state ${row.requirement.route_state}`}>{row.requirement.route_state.replaceAll('-', ' ')}</span></div>}
              {row.targetNativeRoutes.map(route => <div className="target-toolchain-row" key={route.id}><div><span className={`cap-dot ${route.ready ? 'ready' : 'warning'}`} /><strong>{route.id}</strong><small>native route</small></div><code>{Object.values(route.tools).map(tool => tool.path ?? tool.configured.join(' ')).join(' · ')}</code><span className={`evidence-badge ${route.ready ? 'ready' : 'warning'}`}>{route.ready ? 'installed' : 'missing tools'}</span><b>source build</b></div>)}
              {row.targetPackRoutes.map(route => {
                const routeTone = lifecycleTone(route.state);
                return <div className="target-toolchain-row" key={route.id}><div><span className={`cap-dot ${routeTone}`} /><strong>{route.label}</strong><small>{route.compiler_id} · {route.evidence_role}</small></div><code>{route.target_triple}</code><span className={`evidence-badge ${routeTone}`}>{route.state.replaceAll('-', ' ')}</span><b>{route.provisioning.replaceAll('-', ' ')}</b></div>;
              })}
              {row.targetToolchains.map(toolchain => {
                const toolchainTone = toolchain.state === 'verified-cached' ? 'ready' : toolchain.state === 'broken' ? 'warning' : 'cold';
                return <div className="target-toolchain-row" key={toolchain.id}><div><span className={`cap-dot ${toolchainTone}`} /><strong>{toolchain.variant}</strong><small>{toolchain.family} {toolchain.version}</small></div><code>{toolchain.id}</code><span className={`evidence-badge ${toolchainTone}`}>{toolchain.state === 'verified-cached' ? 'checksum-cached' : toolchain.state}</span><b>{toolchain.capabilities.map(value => value === 'source' ? 'cross compiler' : 'libc archive').join(' + ')}</b></div>;
              })}
              {!row.targetNativeRoutes.length && !row.targetToolchains.length && !row.targetPackRoutes.length && <div className="target-gap-row"><span>!</span><p><strong>No registered compiler or archive route</strong><small>The target remains visible so this gap cannot be mistaken for unsupported demand.</small></p></div>}
            </div>
          </details>;
        })}
        {!visibleTargets.length && <div className="empty-state"><span>◇</span><strong>No targets match this view</strong><p>Clear the search or choose a different installation filter.</p></div>}
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
    <ViewIntro kicker="SEALED PROVENANCE" title="Artifacts & provenance" action={<button className="secondary-action" disabled>{snapshot ? `${artifacts.length} preview artifacts` : 'Coordinator offline'}</button>} />
    {snapshot?.result_jobs_truncated && <div className="inline-warning">Showing artifact details for {snapshot.result_jobs_included?.toLocaleString()} recent jobs. Queue state and build coverage still include all {snapshot.result_jobs_total?.toLocaleString()} completed jobs.</div>}
    <div className="evidence-layout">
      <section className="panel artifact-list"><div className="panel-header"><h3>Sealed artifacts</h3><span className="plan-state">LIVE</span></div>
        {artifacts.map(artifact => <button className="artifact-row" key={`${artifact.job.job_id}-${artifact.kind}`}><span className="file-glyph">{artifact.kind.toUpperCase()}</span><div><strong>{artifact.path.split('/').pop()}</strong><small>{artifact.job.base_cell}</small></div><span>{artifact.kind === 'fidbf' ? 'Raw FID export' : artifact.kind === 'fidb' ? 'FID database' : 'Provenance seal'}</span><code>{artifact.sha256.slice(0, 16)}…</code><b>→</b></button>)}
        {!artifacts.length && <div className="empty-state"><span>◇</span><strong>No sealed queue artifacts yet</strong><p>Disarmed or unfinished jobs do not create evidence entries.</p></div>}
      </section>
      <section className="panel provenance-card"><div className="panel-header"><h3>{selected?.base_cell ?? 'No completed cell'}</h3><span className={`worker-state ${selected ? 'ready' : 'offline'}`}>{selected ? 'Sealed' : 'Empty'}</span></div>
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
  const finishStarted = schedulePolicy?.finish_started_batch === true;
  const control = snapshot?.paused
    ? { label: 'Resume claims', action: factory.resume }
    : snapshot?.armed
      ? { label: 'Pause new claims', action: () => factory.pause('operator pause from control panel') }
      : { label: 'Synchronize queue', action: factory.sync };
  return <div className="view-stack">
    <ViewIntro kicker="UNATTENDED OPERATION" title="Automation" action={<button className="secondary-action" onClick={() => void control.action()} disabled={factory.busyAction !== null}>{factory.busyAction ? 'Working…' : control.label}</button>} />
    {factory.error && <div className="toast warning" role="alert">! {factory.error}</div>}
    <div className="automation-layout">
      <section className="panel automation-form">
        <div className="panel-header"><h3>plans/priority-queue.toml</h3><span className={`plan-state ${snapshot?.armed && !snapshot.paused ? 'ready' : ''}`}>{snapshot?.status.toUpperCase() ?? 'NOT SYNCED'}</span></div>
        <div className="policy-body">
          <label className="field-label">Enforced overnight policy</label><div className="mode-grid"><button className="selected" disabled><span>Night</span><small>all configured days</small></button><button disabled><span>{preflight?.schedule.claims_allowed ? 'Claims open' : 'Claims closed'}</span><small>{preflight?.schedule.reason ?? 'not evaluated'}</small></button><button disabled><span>Block drain</span><small>{finishStarted ? `finish after ${stopClaiming}` : 'hard cutoff policy'}</small></button><button disabled><span>{preflight?.resources.passed ? 'Host ready' : 'Host gated'}</span><small>measured before claim</small></button></div>
          <div className="section-divider" />
          <div className="two-fields"><label><span>Start claiming · TOML</span><input type="text" value={startWindow} readOnly /></label><label><span>Stop admitting / active block · TOML</span><input type="text" value={`${stopClaiming} / ${finishStarted ? 'finish' : 'cut off'}`} readOnly /></label></div>
          <div className="two-fields"><label><span>Performance profile · TOML</span><input type="text" value={snapshot?.performance_profile?.id ?? 'unbound'} readOnly /></label><label><span>Maximum active leases · TOML</span><input type="number" value={snapshot?.max_workers ?? 2} readOnly /></label></div>
          <div className="two-fields"><label><span>Build jobs per cell · profile</span><input type="number" value={snapshot?.performance_profile?.settings.build_jobs_per_cell ?? 4} readOnly /></label><label><span>JVM heap ceiling · MiB</span><input type="number" value={snapshot?.performance_profile?.settings.ghidra_heap_mib ?? 4096} readOnly /></label></div>
          <div className="toggle-list">
            <label><div><strong>Library-local pool only</strong><small>Native, explicitly local source-library, and pinned archive-extraction routes. QEMU and malware are excluded.</small></div><input type="checkbox" checked readOnly /></label>
            <label><div><strong>Exponential retry backoff</strong><small>{snapshot?.retry_backoff_seconds ?? '—'}s initial · {snapshot?.retry_backoff_max_seconds ?? '—'}s maximum.</small></div><input type="checkbox" checked={Boolean(snapshot?.retry_backoff_seconds)} readOnly /></label>
            <label><div><strong>Finish an admitted block</strong><small>05:30 stops the next admission; workers and resource gates continue until the current block drains.</small></div><input type="checkbox" checked={finishStarted} readOnly /></label>
            <label><div><strong>Durable notification outbox</strong><small>Failures, retry, drain and resource-block events are retained locally; HTTPS delivery is optional.</small></div><input type="checkbox" checked readOnly /></label>
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
  return <div className="view-stack"><ViewIntro kicker="DURABLE TELEMETRY" title="Activity" action={<button className="secondary-action" disabled>{connection === 'live' ? `${events.length} events` : 'Coordinator offline'}</button>} />
    <section className="panel terminal-panel"><div className="terminal-toolbar"><div><span /><span /><span /></div><code>var/fidb-coordinator/ledger.sqlite3 / events</code><button disabled>{connection === 'live' ? 'Live poll' : 'Not live'}</button></div><div className="terminal-events">{displayed.map(event => <div key={event.event_id}><time>{eventTime(event, true)}</time><span className={`event-dot ${eventTone(event)}`} /><strong>{event.event_type}</strong><p>{eventDetail(event)}</p></div>)}{!displayed.length && <div className="empty-state"><time>—</time><span className="event-dot info"/><strong>No events</strong><p>Synchronize the queue to begin the ledger.</p></div>}</div></section>
  </div>;
}
