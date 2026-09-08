'use client';

import { Fragment, useState, useSyncExternalStore, type CSSProperties } from 'react';
import {
  useFactoryApi,
  type CoordinatorBatch,
  type CoordinatorEvent,
  type CoordinatorJob,
  type CoordinatorSnapshot,
  type CoordinatorWorker,
  type ToolchainProfilePlan,
  type WidthBatch,
} from './use-factory-api';
import {
  formatBytes,
  formatPlanningDurationNs,
} from './formatters';
import { ViewIntro, type FactoryApiState } from './panel-primitives';
import {
  ExportView,
  PerformanceView,
  RetentionView,
  TimingView,
} from './operations-views';
import {
  BatchValidationView,
  EcologicalValidationView,
  HashDiscriminationView,
} from './validation-views';
import { eventDetail, eventTime, eventTone } from './coordinator-presenters';
import { OverviewView } from './overview-view';
import {
  LanguageScopeSelector,
  MatrixView,
  QualificationPipelinePanel,
  TimeBlockPlanPanel,
} from './matrix-view';
import type { BatchRow } from './view-models';

const navItems = [
  ['01', 'Overview'],
  ['02', 'Matrix'],
  ['03', 'Batches'],
  ['04', 'Targets & toolchains'],
  ['05', 'Provenance'],
];

const validationNavItems = [
  ['06', 'Batch validation'],
  ['07', 'Ecological validation'],
  ['08', 'Hash discrimination'],
];


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


function lifecycleTone(state: string) {
  return state === 'qualified' || state === 'prepared' || state === 'bound-verified' || state === 'composed' || state === 'verified-cached' ? 'ready' : state.includes('broken') ? 'warning' : 'cold';
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
            <strong>{factory.capabilities ? `${factory.capabilities.host.system} · ${factory.capabilities.host.machine}` : 'Execution host'}</strong>
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
            <span className="environment-key">STATE</span>
            <div>
              <strong>{factory.snapshot?.status ?? 'Unbound'}</strong>
              <span>{factory.snapshot?.config_name ?? 'coordinator not loaded'}</span>
            </div>
          </div>
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
          </div>
        </header>

        <div className="content-scroll">
          {activeView === 'Overview'
            ? <OverviewView factory={factory} batches={currentBatchRows} navigateTo={setActiveView} />
            : <SecondaryView view={activeView} navigateTo={setActiveView} batchOrder={effectiveBatchOrder} setBatchOrder={setBatchOrder} rows={currentBatchRows} factory={factory} selectedLanguageId={selectedLanguageId} setSelectedLanguageId={setSelectedLanguageId} />}
        </div>
      </section>
    </main>
  );
}

function SecondaryView({ view, navigateTo, batchOrder, setBatchOrder, rows, factory, selectedLanguageId, setSelectedLanguageId }: { view: string; navigateTo: (view: string) => void; batchOrder: string[]; setBatchOrder: React.Dispatch<React.SetStateAction<string[]>>; rows: BatchRow[]; factory: FactoryApiState; selectedLanguageId: string; setSelectedLanguageId: React.Dispatch<React.SetStateAction<string>> }) {
  if (view === 'Matrix') return <MatrixView batchOrder={batchOrder} rows={rows} factory={factory} selectedLanguageId={selectedLanguageId} setSelectedLanguageId={setSelectedLanguageId} />;
  if (view === 'Batch validation') return <BatchValidationView factory={factory} navigateTo={navigateTo} />;
  if (view === 'Ecological validation') return <EcologicalValidationView factory={factory} />;
  if (view === 'Hash discrimination') return <HashDiscriminationView factory={factory} />;
  if (view === 'Performance') return <PerformanceView factory={factory} />;
  if (view === 'Retention') return <RetentionView factory={factory} />;
  if (view === 'Timing') return <TimingView factory={factory} />;
  if (view === 'Export') return <ExportView factory={factory} />;
  if (view === 'Batches') return <BatchesView onNewBatch={() => navigateTo('Matrix')} batchOrder={batchOrder} setBatchOrder={setBatchOrder} rows={rows} live={Boolean(factory.snapshot)} factory={factory} />;
  if (view === 'Targets & toolchains') return <ToolchainsView factory={factory} selectedLanguageId={selectedLanguageId} setSelectedLanguageId={setSelectedLanguageId} />;
  if (view === 'Provenance') return <ProvenanceView snapshot={factory.snapshot} />;
  if (view === 'Automation') return <AutomationView factory={factory} navigateTo={navigateTo} />;
  return <ActivityView events={factory.events} connection={factory.connection} />;
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

function ProvenanceView({ snapshot }: { snapshot: CoordinatorSnapshot | null }) {
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
    <ViewIntro kicker="SEALED PROVENANCE" title="Artifacts & provenance" action={<span className={`validation-state ${snapshot ? 'ready' : 'waiting'}`}>{snapshot ? `${artifacts.length} artifacts` : 'Coordinator offline'}</span>} />
    {snapshot?.result_jobs_truncated && <div className="inline-warning">Showing artifact details for {snapshot.result_jobs_included?.toLocaleString()} recent jobs. Queue state and build coverage still include all {snapshot.result_jobs_total?.toLocaleString()} completed jobs.</div>}
    <div className="evidence-layout">
      <section className="panel artifact-list"><div className="panel-header"><h3>Sealed artifacts</h3><span className="plan-state">LIVE</span></div>
        {artifacts.map(artifact => <article className="artifact-row" key={`${artifact.job.job_id}-${artifact.kind}`}><span className="file-glyph">{artifact.kind.toUpperCase()}</span><div><strong>{artifact.path.split('/').pop()}</strong><small>{artifact.job.base_cell}</small></div><span>{artifact.kind === 'fidbf' ? 'Raw FID export' : artifact.kind === 'fidb' ? 'FID database' : 'Provenance seal'}</span><code>{artifact.sha256.slice(0, 16)}…</code></article>)}
        {!artifacts.length && <div className="empty-state"><span>◇</span><strong>No sealed queue artifacts yet</strong><p>Disarmed or unfinished jobs do not create evidence entries.</p></div>}
      </section>
      <section className="panel provenance-card"><div className="panel-header"><h3>{selected?.base_cell ?? 'No completed cell'}</h3><span className={`worker-state ${selected ? 'ready' : 'offline'}`}>{selected ? 'Sealed' : 'Empty'}</span></div>
        {selected ? <><dl><div><dt>Job</dt><dd className="digest">{selected.job_id}</dd></div><div><dt>Batch</dt><dd>{selected.batch_id}</dd></div><div><dt>Attempts</dt><dd>{selected.attempt_count}</dd></div><div><dt>Worker</dt><dd>{selected.leased_by ?? 'released after seal'}</dd></div><div><dt>Executor</dt><dd>{typeof selectedResult.executor === 'string' ? selectedResult.executor : 'recorded in seal'}</dd></div><div><dt>State</dt><dd>{selected.state}</dd></div></dl><div className="cli-preview"><span>RESULT AUTHORITY</span><code>SQLite ledger + artifacts/runs/{selected.job_id}/…</code></div></> : <div className="empty-state"><span>◇</span><strong>Nothing to inspect</strong><p>Complete a library cell through the worker before provenance is shown.</p></div>}
      </section>
    </div>
  </div>;
}

function AutomationView({ factory, navigateTo }: { factory: FactoryApiState; navigateTo: (view: string) => void }) {
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
  const operationSections = [
    ['Timing', factory.timings?.eta ? 'ETA available' : 'Collecting evidence'],
    ['Performance', factory.capabilities?.automatic_performance ? 'Host resolved' : 'Host unavailable'],
    ['Retention', factory.retention?.latest_plan ? `${factory.retention.latest_plan.summary.actions} planned actions` : 'No active plan'],
    ['Activity', `${factory.events.length} retained events`],
    ['Export', factory.exportStatus?.ready ? 'Ready to package' : 'Not ready'],
  ];
  return <div className="view-stack">
    <ViewIntro kicker="OPERATIONS & UNATTENDED EXECUTION" title="Automation" action={<button className="secondary-action" onClick={() => void control.action()} disabled={factory.busyAction !== null}>{factory.busyAction ? 'Working…' : control.label}</button>} />
    {factory.error && <div className="toast warning" role="alert">! {factory.error}</div>}
    <section className="panel operations-index"><header><h3>Operations</h3><span>LIVE CONTROL SURFACES</span></header><div>{operationSections.map(([view, state]) => <button key={view} onClick={() => navigateTo(view)}><strong>{view}</strong><small>{state}</small><span>→</span></button>)}</div></section>
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
  return <div className="view-stack"><ViewIntro kicker="DURABLE TELEMETRY" title="Activity" action={<span className={`validation-state ${connection === 'live' ? 'ready' : 'waiting'}`}>{connection === 'live' ? `${events.length} events` : 'Coordinator offline'}</span>} />
    <section className="panel terminal-panel"><div className="terminal-toolbar"><div><span /><span /><span /></div><code>var/fidb-coordinator/ledger.sqlite3 / events</code><button disabled>{connection === 'live' ? 'Live poll' : 'Not live'}</button></div><div className="terminal-events">{displayed.map(event => <div key={event.event_id}><time>{eventTime(event, true)}</time><span className={`event-dot ${eventTone(event)}`} /><strong>{event.event_type}</strong><p>{eventDetail(event)}</p></div>)}{!displayed.length && <div className="empty-state"><time>—</time><span className="event-dot info"/><strong>No events</strong><p>Synchronize the queue to begin the ledger.</p></div>}</div></section>
  </div>;
}
