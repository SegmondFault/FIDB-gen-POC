'use client';

import { useEffect, useState } from 'react';

import type { CoordinatorAttempt, CoordinatorSnapshot, FactoryCapabilities, PerformanceProfiles } from './use-factory-api';
import { elapsedNs, etaDuration, formatBytes, formatDurationNs, formatStartedAt, numericMetric, resourceEvidence, stageLabel } from './formatters';
import { PanelReadWarning, ViewIntro, type FactoryApiState } from './panel-primitives';

export function PerformanceView({ factory }: { factory: FactoryApiState }) {
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

export function RetentionView({ factory }: { factory: FactoryApiState }) {
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

export function ExportView({ factory }: { factory: FactoryApiState }) {
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

export function TimingView({ factory }: { factory: FactoryApiState }) {
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
