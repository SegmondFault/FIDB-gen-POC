'use client';

import { useState, type CSSProperties } from 'react';

import type { HashDiscriminationStatus, HashTypeAnalysis, NoisyHashRow } from './use-factory-api';
import { formatBytes } from './formatters';
import { PanelReadWarning, ViewIntro, type FactoryApiState } from './panel-primitives';

function validationRate(numerator: number | null, denominator: number | null) {
  if (numerator === null || denominator === null || denominator === 0) return '—';
  return `${((numerator / denominator) * 100).toFixed(2)}%`;
}

export function BatchValidationView({ factory, navigateTo }: { factory: FactoryApiState; navigateTo: (view: string) => void }) {
  const liveValidation = factory.machineValidation;
  const validationBatches = (factory.authority?.machine_validations ?? (liveValidation ? [liveValidation] : []))
    .map(validation => validation.id === liveValidation?.id ? liveValidation : validation);
  const [selectedBatchId, setSelectedBatchId] = useState(liveValidation?.id ?? validationBatches[0]?.id ?? '');
  const validation = validationBatches.find(validation => validation.id === selectedBatchId)
    ?? liveValidation
    ?? validationBatches[0];
  if (!validation) return <div className="view-stack"><ViewIntro kicker="BATCH VALIDATION" title="Batch validation" action={<span className="validation-state waiting">UNAVAILABLE</span>} /><PanelReadWarning factory={factory} endpoints={['authority', 'machine-validation/run']} /><section className="panel"><div className="empty-state"><span>◇</span><strong>No validation authority loaded</strong><p>Reconnect the local API or add validation/machine-validation.toml.</p></div></section></div>;
  const matrix = validation.results.confusion_matrix;
  const matrixCells = [
    ['TP', 'True positives', matrix.true_positives, 'Expected signature recovered for a present library'],
    ['FP', 'False positives', matrix.false_positives, 'Signature also matched an opposite-fold library'],
    ['TN', 'True negatives', matrix.true_negatives, 'Opposite-fold library correctly did not match'],
    ['FN', 'False negatives', matrix.false_negatives, 'Expected exact signature missing from the composite'],
  ] as const;
  const percent = Math.round((validation.summary.completed_exact_inputs / validation.summary.required_exact_inputs) * 100);
  const run = validation.run;
  const runExpected = run.expected_work_units ?? 0;
  const runPercent = runExpected > 0
    ? Math.round((run.complete_work_units / runExpected) * 100)
    : 0;
  const runNotAttempted = Math.max(0, runExpected - run.complete_work_units - run.failed_work_units);
  const runOutstanding = Math.max(0, runExpected - run.complete_work_units);
  const runPauseable = ['queued', 'preparing-index', 'running', 'pausing'].includes(run.state);
  const runActive = ['queued', 'preparing-index', 'running', 'pausing', 'postprocessing', 'retaining'].includes(run.state);
  const runRecoveryRequired = run.state === 'postprocess-failed';
  const runResumable = ['paused', 'interrupted', 'failed'].includes(run.state)
    && runExpected > run.complete_work_units;
  const capabilityLabel = validation.results.state === 'measured-complete'
    ? 'MEASURED'
    : runActive
      ? run.state.replaceAll('-', ' ').toUpperCase()
      : runResumable
        ? 'RESUMABLE'
        : validation.readiness.eligible
          ? 'READY'
          : 'WAITING';
  const capabilityTone = validation.results.state === 'measured-complete' || validation.readiness.eligible
    ? 'ready'
    : 'waiting';
  const currentBatch = validation.id === liveValidation?.id;
  const reportPending = runExpected > 0 && run.complete_work_units < runExpected;
  const reportState = validation.results.state === 'measured-complete'
    ? 'measured complete'
    : reportPending
      ? 'report pending'
      : validation.results.state === 'invalid-report'
        ? 'report incomplete'
        : 'not run';
  const tp = matrix.true_positives;
  const fp = matrix.false_positives;
  const tn = matrix.true_negatives;
  const fn = matrix.false_negatives;
  const measuredDecisions = [tp, fp, tn, fn].every(value => value !== null)
    ? (tp ?? 0) + (fp ?? 0) + (tn ?? 0) + (fn ?? 0)
    : null;
  const noisyCandidates = factory.noisyHashes?.summary.candidate_noisy ?? null;
  const hashEvidence = validation.results.hash_evidence;
  const fidMatching = validation.fid_matching;
  const fidQualification = fidMatching.qualification;
  const fidCanaryProgress = fidMatching.canary.progress;
  const fidFullProgress = fidMatching.full.progress;
  const startRun = (mode: 'canary' | 'full') => {
    void factory.runMachineValidation(
      mode,
      mode === 'full' ? fidMatching.source_run_id : undefined,
    ).catch(() => undefined);
  };
  const pauseRun = () => {
    void factory.pauseMachineValidation().catch(() => undefined);
  };
  const resumeRun = () => {
    void factory.resumeMachineValidation().catch(() => undefined);
  };
  const folds = [
    ['A', validation.randomization.fold_a],
    ['B', validation.randomization.fold_b],
  ] as const;
  return <div className="view-stack machine-validation-view">
    <ViewIntro kicker="BATCH VALIDATION" title="Batch validation" action={<div className="view-intro-actions"><span className={`validation-state ${capabilityTone}`}>{capabilityLabel}</span>{currentBatch && runPauseable && <button className="secondary-action" onClick={pauseRun} disabled={run.state === 'pausing' || factory.busyAction !== null}>{factory.busyAction === 'machine-validation-pause' || run.state === 'pausing' ? '⏸ Pausing…' : '⏸ Pause'}</button>}{currentBatch && runResumable && <button className="primary-action" onClick={resumeRun} disabled={factory.busyAction !== null}>{factory.busyAction === 'machine-validation-resume' ? '▶ Resuming…' : '▶ Resume'}</button>}<button className="secondary-action" onClick={() => startRun('canary')} disabled={!currentBatch || !validation.readiness.eligible || runActive || runResumable || runRecoveryRequired || factory.busyAction !== null}>{factory.busyAction === 'machine-validation-canary' ? 'Starting…' : 'Run canary'}</button><button className="primary-action" onClick={() => startRun('full')} disabled={!currentBatch || !validation.readiness.eligible || !validation.canary_gate.ready || runActive || runResumable || runRecoveryRequired || factory.busyAction !== null}>{factory.busyAction === 'machine-validation-full' ? 'Starting…' : 'Run full validation'}</button><button className="secondary-action" onClick={() => void factory.refresh()} disabled={factory.connection === 'connecting'}>Refresh</button></div>} />
    <PanelReadWarning factory={factory} endpoints={['authority', 'machine-validation/run', 'noisy-hashes']} />

    <section className="panel validation-batch-panel">
      <header><h3>Cohort validation ledger</h3><span>ONE RESULT SET PER SCIENTIFIC BATCH</span></header>
      <div>{validationBatches.map((batch, index) => {
        const start = index * batch.cohort_policy.nominal_size + 1;
        const end = start + batch.summary.cohort_libraries - 1;
        const selected = batch.id === validation.id;
        const batchRun = batch.id === liveValidation?.id ? liveValidation.run : batch.run;
        return <button className={selected ? 'active' : ''} key={batch.id} onClick={() => setSelectedBatchId(batch.id)} aria-pressed={selected}><span>{String(start).padStart(2, '0')}–{String(end).padStart(2, '0')}</span><p><strong>{batch.label}</strong><small>{batch.id} · {batch.summary.exact_identities} exact identities</small></p><em>{batch.results.state === 'measured-complete' ? 'MEASURED' : batchRun.complete_work_units ? `${batchRun.complete_work_units}/${batchRun.expected_work_units ?? batch.summary.work_units}` : batch.readiness.eligible ? 'READY' : 'WAITING'}</em></button>;
      })}</div>
    </section>

    <section className="panel validation-results-panel validation-outcome-panel"><header><h3>Batch result · {validation.id}</h3><div><button className="text-button" onClick={() => navigateTo('Hash discrimination')}>Corpus-wide hash evidence →</button><span className={`validation-state ${validation.results.state === 'measured-complete' ? 'ready' : 'waiting'}`}>{reportState}</span></div></header>
      <div className="validation-rate-grid"><article><span>PRECISION</span><strong>{validationRate(tp, tp === null || fp === null ? null : tp + fp)}</strong><small>matched signature-owner assertions that were present</small></article><article><span>RECALL</span><strong>{validationRate(tp, tp === null || fn === null ? null : tp + fn)}</strong><small>expected exact signatures recovered</small></article><article><span>FALSE-POSITIVE RATE</span><strong>{validationRate(fp, fp === null || tn === null ? null : fp + tn)}</strong><small>opposite-fold hash-owner checks that matched</small></article><article><span>MEASURED ASSERTIONS</span><strong>{measuredDecisions === null ? '—' : measuredDecisions.toLocaleString()}</strong><small>{reportPending ? `${runOutstanding} work units unresolved` : matrix.unit.replaceAll('-', ' ')}</small></article><article><span>NOISY SIGNATURES</span><strong>{hashEvidence ? hashEvidence.noisy_signatures.toLocaleString() : '—'}</strong><small>{hashEvidence ? `${hashEvidence.multi_owner_signatures.toLocaleString()} multi-owner signatures` : 'awaiting hash evidence'}</small></article><article><span>HASH LEDGER</span><strong>{noisyCandidates === null ? '—' : noisyCandidates.toLocaleString()}</strong><small>review candidates across completed batches</small></article></div>
      <div className="validation-confusion-grid">{matrixCells.map(([short, label, value, detail]) => <article className={short.toLowerCase()} key={short}><span>{short}</span><strong>{value === null ? '—' : value.toLocaleString()}</strong><p><b>{label}</b><small>{detail}</small></p></article>)}</div>
      {hashEvidence && <div className="validation-hash-evidence-strip"><article><span>DISTINCT SIGNATURES</span><strong>{hashEvidence.distinct_signatures.toLocaleString()}</strong></article><article><span>QUERY OBSERVATIONS</span><strong>{hashEvidence.query_signature_observations.toLocaleString()}</strong></article><article><span>MISSED SIGNATURES</span><strong>{hashEvidence.missed_signatures.toLocaleString()}</strong></article><article><span>UNATTRIBUTED HASHES</span><strong>{hashEvidence.unattributed_signatures.toLocaleString()}</strong><small>{hashEvidence.unattributed_query_signatures.toLocaleString()} observations</small></article><article><span>FOLDS</span><strong>{hashEvidence.fold_results.toLocaleString()}</strong></article><article><span>EVIDENCE</span><code>{hashEvidence.database_path}</code></article></div>}
      <details className="validation-failure-ledger"><summary><span><b>Noisy and missed signatures</b><small>Top rows here; every TP, FP and FN is retained in the evidence database</small></span><em>{validation.results.failures.length} VISIBLE · EXPAND</em></summary><div className="validation-failure-head"><span>Type / compatible scope</span><span>Factor spread</span><span>Signature / competing owner</span><span>Evidence database</span></div>{validation.results.failures.map((failure, index) => <article key={`${failure.failure_type}-${failure.function_id}-${index}`}><div><span className={failure.failure_type}>{failure.failure_type}</span><strong>{failure.library_id}</strong><small>{failure.function_id}</small></div><div><strong>{failure.route_id}</strong><small>{failure.compiler_id} · {failure.treatment_id}</small></div><div><code>{failure.signature}</code><small>{failure.candidate_owner || 'no competing owner'}</small></div><code>{failure.evidence_path}</code></article>)}{!validation.results.failures.length && <div className="operational-empty"><strong>{reportPending ? 'Single-hash report pending' : 'No noisy or missed signatures reported'}</strong><small>{reportPending ? `${run.complete_work_units}/${runExpected || validation.summary.work_units} build-analysis units are sealed.` : validation.results.detail}</small></div>}</details>
    </section>

    <section className="panel validation-status-panel">
      <header><h3>Current execution</h3><span className={`validation-state ${run.state === 'complete' ? 'ready' : runActive || runResumable ? 'waiting' : ''}`}>{run.state.replaceAll('-', ' ')}</span></header>
      <div className="validation-run-strip"><article><span>MODE / RUN</span><strong>{run.mode?.toUpperCase() ?? '—'}</strong><small>{run.run_id ?? 'no run admitted'}</small></article><article><span>SEALED</span><strong>{run.complete_work_units} / {runExpected || '—'}</strong><small>{runOutstanding} unresolved</small></article><article><span>FAILED</span><strong>{run.failed_work_units}</strong><small>retained for retry</small></article><article><span>WORKERS</span><strong>{runActive ? run.worker_pids?.length ?? 0 : 0}</strong><small>{run.state === 'paused' ? 'checkpointed and quiet' : 'isolated processes'}</small></article><article><span>CANARY</span><strong>{validation.canary_gate.ready ? 'PASS' : 'REQUIRED'}</strong><small>{validation.canary_gate.run_id ?? 'runtime unqualified'}</small></article><article><span>TIME</span><strong>{run.started_at ? new Date(run.started_at).toLocaleTimeString() : '—'}</strong><small>{run.paused_at ? `paused ${new Date(run.paused_at).toLocaleTimeString()}` : run.finished_at ? `finished ${new Date(run.finished_at).toLocaleTimeString()}` : 'local time'}</small></article></div>
      <div className="validation-progress"><span style={{ width: `${runPercent}%` }} /><b>{runPercent}% sealed · {run.complete_work_units} complete · {run.failed_work_units} failed · {runNotAttempted} not attempted</b></div>
      {run.postprocess_job && <div className="validation-postprocess-strip"><strong>{run.postprocess_job.id}</strong>{run.postprocess_job.stages.map(stage => <span className={stage.state} key={stage.id}>{stage.id.replaceAll('-', ' ')} <b>{stage.state}</b></span>)}</div>}
      {run.error && <div className="validation-blockers"><span>! {run.error}</span></div>}
    </section>

    <details className="panel validation-provenance">
      <summary><span><b>Method, processing and reproducibility</b><small>{validation.summary.complete_libraries}/{validation.summary.cohort_libraries} libraries · {validation.summary.completed_exact_inputs.toLocaleString()}/{validation.summary.required_exact_inputs.toLocaleString()} exact inputs · seed and authority frozen</small></span><em>EXPAND</em></summary>
      <div>
        <section className="validation-results-panel fid-matching-panel">
          <header><h3>Native FID methodology · {fidMatching.id}</h3><span className={`validation-state ${fidQualification.state === 'qualified' ? 'ready' : 'waiting'}`}>{fidMatching.state.replaceAll('-', ' ')}</span></header>
          <div className="validation-rate-grid">
            <article><span>ORACLE</span><strong>{fidQualification.state === 'qualified' ? 'QUALIFIED' : fidQualification.state.toUpperCase()}</strong><small>{fidQualification.oracle ? `${fidQualification.oracle.functions.toLocaleString()} functions · ${fidQualification.oracle.candidate_rows.toLocaleString()} candidates` : 'native Ghidra evidence pending'}</small></article>
            {(fidQualification.backends ?? []).map(backend => <article key={backend.id}><span>{backend.id}</span><strong>{backend.decision_mismatches}</strong><small>decision mismatches · max {backend.maximum_score_float32_ulps} float32 ULP</small></article>)}
            <article><span>CANARY</span><strong>{fidCanaryProgress.complete_cases} / {fidCanaryProgress.expected_cases}</strong><small>{fidMatching.canary.state.replaceAll('-', ' ')} · zero-mismatch gate</small></article>
            <article><span>FULL BATCH</span><strong>{fidFullProgress.complete_cases} / {fidFullProgress.expected_cases}</strong><small>{fidMatching.workers} workers · resumes retained cases</small></article>
            <article><span>NEXT WINDOW</span><strong>{fidMatching.schedule.window[0]?.start ?? '—'}–{fidMatching.schedule.window[0]?.stop_admitting ?? '—'}</strong><small>{fidMatching.schedule.timezone} · admitted work finishes</small></article>
          </div>
          {fidQualification.classification && <div className="validation-confusion-grid">{([
            ['tp', 'TP', fidQualification.classification.true_positives, 'Correct library owner accepted'],
            ['fp', 'FP', fidQualification.classification.false_positives, 'Incorrect library owner accepted'],
            ['tn', 'TN', fidQualification.classification.true_negatives, 'Incorrect library owner rejected'],
            ['fn', 'FN', fidQualification.classification.false_negatives, 'True library owner not accepted'],
          ] as const).map(([kind, short, value, detail]) => <article className={kind} key={kind}><span>{short}</span><strong>{value.toLocaleString()}</strong><p><b>{detail}</b><small>query-function × library-owner</small></p></article>)}</div>}
          <footer className="validation-hash-evidence-strip"><article><span>TRUTH</span><strong>linker map → unique name</strong><small>unresolved functions retained, not scored</small></article><article><span>HASH TYPES</span><strong>{fidMatching.methodology.retain_hash_types.join(' · ')}</strong><small>per-decision observations retained</small></article><article><span>SOURCE</span><code>{fidMatching.source_run_id}</code></article></footer>
        </section>
        <section className="validation-status-panel"><header><h3>{validation.label} · {validation.id}</h3><span className={`validation-state ${validation.readiness.eligible ? 'ready' : 'waiting'}`}>{validation.state.replaceAll('-', ' ')}</span></header><div className="validation-headline-metrics"><article><span>COMPLETE LIBRARIES</span><strong>{validation.summary.complete_libraries} / {validation.summary.cohort_libraries}</strong><small>full-width gate</small></article><article><span>EXACT INPUTS</span><strong>{validation.summary.completed_exact_inputs.toLocaleString()} / {validation.summary.required_exact_inputs.toLocaleString()}</strong><small>{percent}% complete</small></article><article><span>LIVE WIDTH</span><strong>{validation.summary.exact_identities}</strong><small>baseline {validation.summary.baseline_exact_identities} · delta {validation.summary.width_delta_from_baseline >= 0 ? '+' : ''}{validation.summary.width_delta_from_baseline}</small></article><article><span>AUTO-SCHEDULE</span><strong>{validation.batch.automatic_scheduling ? 'ENABLED' : 'OFF'}</strong><small>after sealed cohort</small></article><article><span>FINAL PARTIAL</span><strong>{validation.cohort_policy.final_partial_override ? 'OVERRIDE' : 'OFF'}</strong><small>{validation.cohort_policy.final_partial_override ? validation.cohort_policy.final_partial_justification : 'TOML exception for final 2–9'}</small></article><article><span>PLANNING WALL</span><strong>≈{validation.planning.central_wall_hours.toFixed(0)} h</strong><small>{validation.planning.lower_wall_hours}–{validation.planning.upper_wall_hours} h unmeasured range</small></article></div>{validation.readiness.blockers.length > 0 && <div className="validation-blockers">{validation.readiness.blockers.map(blocker => <span key={blocker}>! {blocker}</span>)}</div>}</section>
        <section className="validation-flow-panel"><header><h3>Validation stages</h3><code>{validation.status_digest.slice(0, 16)}…</code></header><div>{validation.stages.map((stage, index) => <article className={stage.state} key={stage.id}><b>{String(index + 1).padStart(2, '0')}</b><p><strong>{stage.label}</strong><small>{stage.detail}</small></p><span>{stage.state.replaceAll('-', ' ')}</span></article>)}</div></section>
        <div className="validation-two-column"><section className="validation-fold-panel"><header><h3>Frozen assignment</h3><code>{validation.randomization.algorithm}</code></header><div>{folds.map(([fold, libraries]) => <section key={fold}><span>FOLD {fold}</span>{libraries.map(identity => { const library = validation.libraries.find(row => row.id === identity); return <article key={identity}><p><strong>{identity}</strong><small>{library?.completed_exact_identities ?? 0} / {library?.required_exact_identities ?? validation.summary.exact_identities} identities</small></p><em className={library?.state}>{library?.state.replaceAll('-', ' ')}</em></article>; })}</section>)}</div><footer>Seed <code>{validation.randomization.seed}</code></footer></section><section className="validation-contract-panel"><header><h3>Query contract · {validation.summary.composite_programs} composites · {validation.summary.query_projections.toLocaleString()} projections</h3><span>NO TARGET EXECUTION</span></header><div>{validation.queries.primary_projections.map((projection, index) => <article key={projection}><b>{index + 1}</b><p><strong>{projection.replaceAll('-', ' ')}</strong><small>{index === 0 ? 'Positive recovery with the exact build identity withheld' : index === 1 ? 'Negative attribution and shared-signature pressure' : 'Owner competition against every indexed candidate library'}</small></p></article>)}</div><dl><div><dt>Input strategy</dt><dd>{validation.batch.input_strategy}</dd></div><div><dt>Truth / query</dt><dd>{validation.batch.truth_copy} / {validation.batch.query_copy}</dd></div><div><dt>RAM budget</dt><dd>{validation.planning.safe_ram_gib_lower}–{validation.planning.safe_ram_gib_upper} GiB</dd></div><div><dt>Scratch headroom</dt><dd>{validation.planning.scratch_headroom_gib_lower}–{validation.planning.scratch_headroom_gib_upper} GiB</dd></div></dl></section></div>
      </div>
    </details>

    <section className="panel ecological-boundary"><span>FINAL DATASET GATE</span><p><strong>{validation.ecological_validation.mode.replaceAll('-', ' ')}</strong><small>{validation.ecological_validation.gate.replaceAll('-', ' ')}</small></p><em>{validation.ecological_validation.state.replaceAll('-', ' ')}</em></section>
  </div>;
}

function splitOwnerLabels(value: string) {
  return Array.from(new Set(value.split(/[\s,]+/).map(item => item.trim()).filter(Boolean)));
}

export function EcologicalValidationView({ factory }: { factory: FactoryApiState }) {
  const validation = factory.ecologicalValidation;
  const [file, setFile] = useState<File | null>(null);
  const [label, setLabel] = useState('');
  const [platformHint, setPlatformHint] = useState('auto');
  const [expectedPresent, setExpectedPresent] = useState('');
  const [expectedAbsent, setExpectedAbsent] = useState('');
  const [truthComplete, setTruthComplete] = useState(false);
  const [message, setMessage] = useState('');
  if (!validation) return <div className="view-stack"><ViewIntro kicker="ECOLOGICAL VALIDATION" title="Ecological validation" action={<span className="validation-state waiting">UNAVAILABLE</span>} /><PanelReadWarning factory={factory} endpoints={['ecological-validation']} /><section className="panel"><div className="empty-state"><span>◇</span><strong>No ecological authority loaded</strong><p>Reconnect the local API or inspect validation/ecological-validation.toml.</p></div></section></div>;
  const matrix = validation.aggregate.confusion_matrix;
  const matrixCells = [
    ['TP', 'True positives', matrix.true_positives, 'Expected corpus library detected'],
    ['FP', 'False positives', matrix.false_positives, 'Unexpected owner detected · collision'],
    ['TN', 'True negatives', matrix.true_negatives, 'Expected-absent owner rejected'],
    ['FN', 'False negatives', matrix.false_negatives, 'Expected library not detected'],
  ] as const;
  const importing = factory.busyAction === 'ecological-import';
  const ecologicalCapability = validation.summary.running_cases
    ? 'RUNNING'
    : validation.aggregate.measured_cases
      ? 'MEASURED'
      : validation.corpus.materialized_generations
        ? 'READY'
        : 'WAITING';
  const importFile = async () => {
    if (!file || !label.trim()) return;
    setMessage('Importing and routing preserved bytes…');
    try {
      await factory.importEcological(file, {
        label: label.trim(),
        platformHint,
        expectedPresent: splitOwnerLabels(expectedPresent),
        expectedAbsent: splitOwnerLabels(expectedAbsent),
        truthComplete,
      });
      setMessage('Imported. The corpus gate below determines whether it can run.');
      setFile(null);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Import failed.');
    }
  };
  return <div className="view-stack ecological-validation-view">
    <ViewIntro kicker="HELD-OUT ECOLOGICAL VALIDATION" title="Ecological validation" action={<div className="view-intro-actions"><span className={`validation-state ${ecologicalCapability === 'WAITING' ? 'waiting' : 'ready'}`}>{ecologicalCapability}</span><button className="secondary-action" onClick={() => void factory.refresh()}>Refresh</button></div>} />
    <PanelReadWarning factory={factory} endpoints={['ecological-validation']} />

    <section className="panel ecological-corpus-panel">
      <header><h3>Corpus</h3><span className={`validation-state ${validation.corpus.materialized_generations ? 'ready' : 'waiting'}`}>{validation.corpus.materialized_generations ? 'CORPUS PRESENT' : 'NO CORPUS YET'}</span></header>
      <div className="ecological-corpus-metrics"><article><span>GENERATIONS</span><strong>{validation.corpus.materialized_generations}</strong><small>{validation.corpus.active_packs} active packs</small></article><article><span>RAW OBSERVATIONS</span><strong>{validation.corpus.raw_observations.toLocaleString()}</strong><small>occurrence-preserving evidence</small></article><article><span>COMPACT SIGNATURES</span><strong>{validation.corpus.compact_unique_signatures.toLocaleString()}</strong><small>deduplicated compatible identities</small></article><article><span>STORAGE</span><strong>{formatBytes(validation.corpus.bytes)}</strong><small>{validation.corpus.issues} inventory issues</small></article><article><span>CASES</span><strong>{validation.summary.completed_cases} / {validation.summary.imported_cases}</strong><small>{validation.summary.running_cases} running · {validation.summary.ready_cases} ready</small></article></div>
    </section>

    <section className="panel ecological-import-panel">
      <header><h3>Import held-out binary · ELF / PE/COFF / thin Mach-O · max {formatBytes(validation.policy.max_file_bytes)}</h3><span>SHA-256 PINNED · NEVER EXECUTED</span></header>
      <div className="ecological-import-grid">
        <label className="ecological-file-input"><span>BINARY FILE</span><input type="file" onChange={event => { const selected = event.target.files?.[0] ?? null; setFile(selected); if (selected && !label) setLabel(selected.name); }} /><strong>{file ? `${file.name} · ${formatBytes(file.size)}` : 'Choose one held-out binary'}</strong></label>
        <label><span>CASE LABEL</span><input value={label} maxLength={128} onChange={event => setLabel(event.target.value)} placeholder="Known OpenSSL-positive utility" /></label>
        <label><span>PLATFORM HINT</span><select value={platformHint} onChange={event => setPlatformHint(event.target.value)}><option value="auto">Auto</option><option value="linux">Linux</option><option value="android">Android</option><option value="windows">Windows</option><option value="macos">macOS</option><option value="ios">iOS</option></select></label>
        <label><span>EXPECTED PRESENT</span><textarea value={expectedPresent} onChange={event => setExpectedPresent(event.target.value)} placeholder="openssl@3.5.8, zlib@1.3.1" /></label>
        <label><span>EXPECTED ABSENT</span><textarea value={expectedAbsent} onChange={event => setExpectedAbsent(event.target.value)} placeholder="Explicit negatives only" /></label>
        <label className="ecological-truth-toggle"><input type="checkbox" checked={truthComplete} onChange={event => setTruthComplete(event.target.checked)} /><span><strong>Ground truth is complete</strong><small>All unlisted corpus owners become expected negatives. Leave off for partial knowledge.</small></span></label>
      </div>
      <footer><p>{message || 'Unlabelled imports are permitted for exploration, but TP/FP/TN/FN remain blank.'}</p><button className="primary-action" onClick={() => void importFile()} disabled={!file || !label.trim() || importing}>{importing ? 'Importing…' : 'Import binary'}</button></footer>
    </section>

    <section className="panel validation-results-panel"><header><h3>Decision matrix</h3><span className={`validation-state ${validation.aggregate.measured_cases ? 'ready' : 'waiting'}`}>{validation.aggregate.measured_cases} measured cases</span></header><div className="validation-confusion-grid">{matrixCells.map(([short, name, value, detail]) => <article className={short.toLowerCase()} key={short}><span>{short}</span><strong>{value === null ? '—' : value.toLocaleString()}</strong><p><b>{name}</b><small>{detail}</small></p></article>)}</div></section>

    <section className="panel ecological-case-panel"><header><h3>Cases · {validation.summary.imported_cases} preserved binaries</h3><code>{validation.status_digest.slice(0, 16)}…</code></header><div className="ecological-case-list">{validation.cases.map(item => {
      const caseMatrix = item.results.confusion_matrix;
      const running = item.state === 'queued' || item.state === 'running';
      return <details key={item.case_id}><summary><span className={`operational-state ${item.results.state === 'measured-complete' ? 'built' : item.readiness.ready_to_run ? 'ready' : 'blocked'}`}>{item.results.state === 'measured-complete' ? 'MEASURED' : running ? item.state.toUpperCase() : item.readiness.ready_to_run ? 'READY' : 'BLOCKED'}</span><p><strong>{item.label}</strong><small>{item.binary.original_filename} · {formatBytes(item.binary.bytes)} · {item.probe.binary_format} {item.probe.architecture ?? ''} {item.probe.bits ?? ''}-bit · {item.probe.sublane_id ?? 'unrouted'}</small></p><div><b>{item.results.failure_summary.collisions}</b><span>collisions</span></div><div><b>{item.results.failure_summary.misses}</b><span>misses</span></div><em>EXPAND</em></summary><section><div className="ecological-case-truth"><p><span>EXPECTED PRESENT</span><strong>{item.truth.expected_present.join(', ') || 'unlabelled'}</strong></p><p><span>EXPECTED ABSENT</span><strong>{item.truth.complete ? 'all unlisted corpus owners' : item.truth.expected_absent.join(', ') || 'unlabelled'}</strong></p><p><span>ROUTING</span><strong>{item.probe.target_id ?? item.probe.blocker ?? 'unresolved'} → {item.probe.lane_id ?? 'no lane'}</strong></p><p><span>CORPUS</span><strong>{item.corpus.map(row => row.generation_id).join(', ') || 'not available'}</strong></p></div>{item.readiness.blockers.length > 0 && <div className="validation-blockers">{item.readiness.blockers.map(blocker => <span key={blocker}>! {blocker}</span>)}</div>}<div className="ecological-case-actions"><span>TP {caseMatrix.true_positives ?? '—'} · FP {caseMatrix.false_positives ?? '—'} · TN {caseMatrix.true_negatives ?? '—'} · FN {caseMatrix.false_negatives ?? '—'}</span><button onClick={() => void factory.runEcological(item.case_id)} disabled={!item.readiness.ready_to_run || running || factory.busyAction === `ecological-run:${item.case_id}`}>{running ? 'Running…' : item.results.state === 'measured-complete' ? 'Run again' : 'Check entire corpus'}</button></div>{item.run.error && <div className="inline-warning">{item.run.error}</div>}<div className="ecological-owner-list">{item.results.owner_matches.map(owner => <article key={owner.owner}><span className={owner.truth}>{owner.truth}</span><p><strong>{owner.owner}</strong><small>{owner.matched_functions} target functions · {owner.matched_occurrences} corpus occurrences</small></p></article>)}{item.results.state === 'measured-complete' && !item.results.owner_matches.length && <div className="operational-empty"><strong>No corpus owners matched</strong><small>Inspect miss rows and target hashability before interpreting this as a true negative.</small></div>}</div><details className="validation-failure-ledger"><summary><span><b>Specific collisions and misses</b><small>{item.results.failures.length} visible rows</small></span><em>EXPAND</em></summary><div className="validation-failure-head"><span>Type / owner / function</span><span>Exact build evidence</span><span>Signature</span><span>Evidence</span></div>{item.results.failures.map((failure, index) => <article key={`${failure.failure_type}-${index}`}><div><span className={failure.failure_type}>{failure.failure_type}</span><strong>{failure.owner}</strong><small>{failure.target_function || 'expected owner absent'}</small></div><div><strong>{failure.route_id}</strong><small>{failure.compiler_id} · {failure.treatment_id}</small></div><code>{failure.signature || '—'}</code><code>{failure.evidence_path}</code></article>)}</details></section></details>;
    })}{!validation.cases.length && <div className="operational-empty"><strong>No held-out files imported</strong><small>Importing is safe before the corpus exists; checking remains fail-closed until a compatible lane generation is available.</small></div>}</div></section>
  </div>;
}

function hdiMeasure(value: number | null, suffix = '') {
  return value === null ? '—' : `${value.toLocaleString()}${suffix}`;
}

function HashFormulaPanel({ hdi }: { hdi: HashDiscriminationStatus }) {
  const componentList = (label: string, components: HashDiscriminationStatus['hdi_components']) => <section><header><span>{label}</span><code>Σ value × weight</code></header><div>{components.map(component => <article key={component.id} style={{ '--hdi-weight': `${component.weight_percent}%` } as CSSProperties}><b>{component.weight_percent}%</b><p><strong>{component.label}</strong><code>{component.calculation}</code></p><span /></article>)}</div></section>;
  return <section className="panel hdi-formula-panel">
    <header><h3>HDI calculation</h3><span>{hdi.reproducibility.algorithm_id} · {hdi.model.component_value_minimum}–{hdi.model.component_value_maximum} inputs</span></header>
    <div className="hdi-formula-columns">{componentList('HASH DISCRIMINATION INDEX · HIGHER IS BETTER', hdi.hdi_components)}{componentList('NOISE RISK · HIGHER IS WORSE', hdi.noise_components)}</div>
    <footer><p><strong>N</strong><span>distinct library families in the compatible corpus</span></p><p><strong>df</strong><span>families containing this signature</span></p><p><strong>α / β</strong><span>{hdi.model.smoothing_alpha} / {hdi.model.smoothing_beta} smoothing prevents tiny samples from implying certainty</span></p><p><strong>Identity</strong><span>complete signature × compatible sublane × candidate owner × corpus generation</span></p></footer>
  </section>;
}

function observedPercent(value: number | null | undefined) {
  return value === null || value === undefined ? '—' : `${(value * 100).toFixed(3)}%`;
}

function HashPopulationTail({ rows }: { rows: HashTypeAnalysis[] }) {
  const width = 720;
  const height = 190;
  const left = 38;
  const right = 18;
  const top = 18;
  const bottom = 34;
  const distributions = rows.flatMap(row => row.distribution ?? []);
  const maximumOwners = Math.max(1, ...distributions.map(row => row.distinct_owners));
  const maximumLogValues = Math.max(1, ...distributions.map(row => Math.log10(row.distinct_values + 1)));
  const x = (owners: number) => left + ((owners - 1) / Math.max(1, maximumOwners - 1)) * (width - left - right);
  const y = (values: number) => top + (1 - Math.log10(values + 1) / maximumLogValues) * (height - top - bottom);
  const colors = { full: '#4ad7da', specific: '#b2a6ef', complete: '#65d68b' } as const;
  return <div className="hash-tail-chart">
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Hash component library-prevalence distribution">
      <line x1={left} x2={width - right} y1={height - bottom} y2={height - bottom} />
      <line x1={left} x2={left} y1={top} y2={height - bottom} />
      {rows.map(row => {
        const points = (row.distribution ?? []).map(point => `${x(point.distinct_owners)},${y(point.distinct_values)}`).join(' ');
        return <g key={row.hash_type}>
          <polyline points={points} fill="none" stroke={colors[row.hash_type]} strokeWidth="2" />
          {(row.distribution ?? []).map(point => <circle key={`${row.hash_type}-${point.distinct_owners}`} cx={x(point.distinct_owners)} cy={y(point.distinct_values)} r="2.5" fill={colors[row.hash_type]} />)}
        </g>;
      })}
      <text x={left} y={height - 10}>1 owner</text>
      <text x={width - right} y={height - 10} textAnchor="end">{maximumOwners} owners</text>
      <text x="9" y={top + 5}>more values</text>
    </svg>
    <div>{rows.map(row => <span key={row.hash_type}><i style={{ background: colors[row.hash_type] }} />{row.hash_type}</span>)}</div>
  </div>;
}

function HashLibraryPopulation({ row }: { row: HashTypeAnalysis }) {
  const libraries = [...(row.libraries ?? [])]
    .sort((left, right) => right.multi_owner_values - left.multi_owner_values || right.missed_observations - left.missed_observations)
    .slice(0, 10);
  const maximum = Math.max(1, ...libraries.map(library => library.multi_owner_values));
  return <div className="hash-library-population">
    <header><span>LIBRARY</span><span>AMBIGUOUS {row.hash_type.toUpperCase()} VALUES</span><span>MISSES</span><span>EXACT FP</span></header>
    {libraries.map(library => <article key={library.owner}><strong>{library.owner}</strong><div><i style={{ width: `${(library.multi_owner_values / maximum) * 100}%` }} /><b>{library.multi_owner_values.toLocaleString()} · {observedPercent(library.ambiguous_fraction)}</b></div><span>{library.missed_observations.toLocaleString()}</span><span>{library.exact_false_positive_observations.toLocaleString()}</span></article>)}
  </div>;
}

function HashNoisePopulationGraph({ row }: { row: HashTypeAnalysis }) {
  type ConcentrationPoint = NonNullable<HashTypeAnalysis['false_positive_concentration']>[number];
  const population = row.noise_population;
  const points = row.false_positive_concentration ?? [];
  if (!population) return null;
  const width = 620;
  const height = 205;
  const left = 42;
  const right = 18;
  const top = 18;
  const bottom = 34;
  const x = (fraction: number) => left + fraction * (width - left - right);
  const y = (fraction: number) => top + (1 - fraction) * (height - top - bottom);
  const closest = (target: number) => points.reduce<ConcentrationPoint | null>((best, point) => !best || Math.abs(point.noisy_hash_fraction - target) < Math.abs(best.noisy_hash_fraction - target) ? point : best, null);
  const anchors = [0.01, 0.1, 0.25, 0.5].map(target => ({ target, point: closest(target) }));
  const topTen = closest(0.1);
  const topHalf = closest(0.5);
  const segments = [
    { id: 'noisy', label: 'FP-bearing', values: population.noisy_values, fraction: population.noisy_fraction ?? 0 },
    { id: 'shared', label: 'multi-owner · 0 FP', values: population.other_multi_owner_values, fraction: population.other_multi_owner_fraction ?? 0 },
    { id: 'single', label: 'single-owner', values: population.single_owner_values, fraction: population.single_owner_fraction ?? 0 },
  ];
  return <section className="panel hash-noise-population-panel">
    <header><h3>{row.hash_type} noisy hash population</h3><span>POPULATION SHARE × CUMULATIVE FP BURDEN</span></header>
    <div className="hash-noise-population-grid">
      <div className="hash-noise-share">
        <div className="hash-noise-primary-metrics">
          <article><span>FP-BEARING HASHES</span><strong>{population.noisy_values.toLocaleString()}</strong><small>{observedPercent(population.noisy_fraction)} of {row.distinct_values.toLocaleString()}</small></article>
          <article><span>FP OBSERVATIONS</span><strong>{population.false_positive_observations.toLocaleString()}</strong><small>{observedPercent(population.false_positive_fraction)} carried by FP-bearing hashes</small></article>
          <article><span>TOP 10% NOISY</span><strong>{topTen ? observedPercent(topTen.false_positive_fraction) : '—'}</strong><small>of observed FP burden</small></article>
          <article><span>TOP 50% NOISY</span><strong>{topHalf ? observedPercent(topHalf.false_positive_fraction) : '—'}</strong><small>of observed FP burden</small></article>
        </div>
        <div className="hash-noise-stack" role="img" aria-label={`${observedPercent(population.noisy_fraction)} of ${row.hash_type} hashes produced at least one false positive`}>
          {segments.map(segment => <i key={segment.id} className={segment.id} style={{ width: `${segment.fraction * 100}%` }} />)}
        </div>
        <div className="hash-noise-legend">{segments.map(segment => <span key={segment.id}><i className={segment.id} /><b>{segment.label}</b><em>{segment.values.toLocaleString()} · {observedPercent(segment.fraction)}</em></span>)}</div>
      </div>
      <div className="hash-fp-concentration">
        {points.length > 1 ? <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Cumulative false-positive burden ranked across ${population.noisy_values.toLocaleString()} noisy ${row.hash_type} hashes`}>
          {[0.25, 0.5, 0.75, 1].map(fraction => <line className="grid" key={`y-${fraction}`} x1={left} x2={width - right} y1={y(fraction)} y2={y(fraction)} />)}
          <line className="axis" x1={left} x2={width - right} y1={height - bottom} y2={height - bottom} />
          <line className="axis" x1={left} x2={left} y1={top} y2={height - bottom} />
          <line className="equal" x1={x(0)} x2={x(1)} y1={y(0)} y2={y(1)} />
          <polyline className="burden" points={points.map(point => `${x(point.noisy_hash_fraction)},${y(point.false_positive_fraction)}`).join(' ')} />
          {anchors.map(({ target, point }) => point && <g key={target}><circle cx={x(point.noisy_hash_fraction)} cy={y(point.false_positive_fraction)} r="3"><title>{`Top ${observedPercent(point.noisy_hash_fraction)}: ${observedPercent(point.false_positive_fraction)} of false positives`}</title></circle><text x={x(point.noisy_hash_fraction)} y={Math.max(top + 8, y(point.false_positive_fraction) - 7)} textAnchor={target > 0.4 ? 'end' : 'start'}>{observedPercent(point.false_positive_fraction)}</text></g>)}
          <text x={left} y={height - 10}>0%</text><text x={x(0.5)} y={height - 10} textAnchor="middle">50% of noisy hashes</text><text x={width - right} y={height - 10} textAnchor="end">100%</text>
          <text x="8" y={top + 4}>100% FP</text><text x="15" y={y(0.5) + 2}>50%</text>
        </svg> : <div className="operational-empty"><strong>FP concentration unavailable</strong><small>The selected batch has no retained per-hash FP population.</small></div>}
      </div>
    </div>
  </section>;
}

function ValidationObservatoryPanel({ factory }: { factory: FactoryApiState }) {
  const observatory = factory.validationObservatory;
  const selected = observatory?.selected;
  const [selectedHashType, setSelectedHashType] = useState<HashTypeAnalysis['hash_type']>('complete');
  const hashTypes = selected?.hash_type_analysis ?? [];
  const activeType = hashTypes.find(row => row.hash_type === selectedHashType) ?? hashTypes[0];
  if (!observatory || observatory.state === 'awaiting-evidence') {
    return <section className="panel validation-observatory-panel"><header><h3>Validation evidence</h3><span>0 MEASURED RUNS</span></header><div className="operational-empty"><strong>Single-hash report pending</strong><small>Full, specific and complete-signature populations will appear after the scheduled corrected analysis.</small></div></section>;
  }
  const matrix = selected?.confusion_matrix;
  return <>
    <section className="panel validation-observatory-panel">
      <header><h3>Validation evidence</h3><span>{observatory.summary.measured_runs} RUNS · {observatory.summary.validation_cohorts} COHORTS</span></header>
      <div className="validation-run-trend"><div className="validation-run-trend-head"><span>Batch / run</span><span>Full ambiguity</span><span>Specific ambiguity</span><span>Complete ambiguity</span><span>FPR</span><span>Recall</span></div>
      <div className="validation-run-selector">{observatory.runs.map(run => {
        const byType = Object.fromEntries(run.hash_types.map(row => [row.hash_type, row]));
        return <button key={run.key} className={run.key === observatory.selected_run_key ? 'active' : ''} onClick={() => void factory.selectValidationRun(run.key)}><p><span>{run.validation_id}</span><strong>{run.run_id}</strong><small>{run.finished_at ? new Date(run.finished_at).toLocaleString() : 'time unavailable'}</small></p><b>{observedPercent(byType.full?.multi_owner_fraction)}</b><b>{observedPercent(byType.specific?.multi_owner_fraction)}</b><b>{observedPercent(byType.complete?.multi_owner_fraction)}</b><b>{observedPercent(run.rates.false_positive_rate)}</b><b>{observedPercent(run.rates.true_positive_rate)}</b></button>;
      })}</div></div>
      {selected && matrix && <>
        <div className="validation-job-chain"><span>BATCH <b>{selected.validation_id}</b></span><i>→</i><span>BUILD + ANALYSE <b>222 WIDTH UNITS</b></span><i>→</i><span>HASH JOB <b>{selected.pipeline_job?.state.replaceAll('-', ' ') ?? 'evidence published'}</b></span><i>→</i><span>CORPUS <b>{selected.corpus_index ? `G${selected.corpus_index.ordinal}` : '—'}</b></span><i>→</i><span>RETENTION <b>{selected.pipeline_job?.stages.find(stage => stage.id === 'retention')?.state ?? 'recorded separately'}</b></span></div>
        <div className="construct-validity-alert"><strong>FNR is harness-conditional</strong><span>{selected.construct_validity?.reference_unit?.replaceAll('-', ' ') ?? 'per library archive functions'} → {selected.construct_validity?.query_unit?.replaceAll('-', ' ') ?? 'five library linked composite functions'}</span><b>{selected.construct_validity?.route_false_negative_rate_spread === null || selected.construct_validity?.route_false_negative_rate_spread === undefined ? 'ROUTE DIAGNOSTIC NOT RETAINED IN THIS LEGACY REPORT' : `${observedPercent(selected.construct_validity.route_false_negative_rate_spread)} ROUTE SPREAD`}</b></div>
        <div className="observatory-outcomes">
          <article><span>TP</span><strong>{matrix.true_positives.toLocaleString()}</strong><small>{observedPercent(selected.rates.true_positive_rate)} recall</small></article>
          <article><span>FP</span><strong>{matrix.false_positives.toLocaleString()}</strong><small>{observedPercent(selected.rates.false_positive_rate)} FPR</small></article>
          <article><span>TN</span><strong>{matrix.true_negatives.toLocaleString()}</strong><small>{observedPercent(selected.rates.true_negative_rate)} specificity</small></article>
          <article><span>FN</span><strong>{matrix.false_negatives.toLocaleString()}</strong><small>{observedPercent(selected.rates.false_negative_rate)} miss rate</small></article>
          <article><span>PRECISION</span><strong>{observedPercent(selected.rates.precision)}</strong><small>single-signature assertions</small></article>
          <article><span>METHOD</span><strong>{selected.method_authority?.id ?? 'legacy'}</strong><small>{selected.method_authority?.sha256?.slice(0, 12) ?? 'unpinned'} · report {selected.report_sha256.slice(0, 12)}</small></article>
          {selected.corpus_index && <article><span>CORPUS GENERATION</span><strong>G{selected.corpus_index.ordinal}</strong><small>{selected.corpus_index.owners} owners · {selected.corpus_index.signatures.toLocaleString()} signatures</small></article>}
          {selected.lookup_backend && <article><span>LOOKUP BACKEND</span><strong>{selected.lookup_backend.device.toUpperCase()}</strong><small>{selected.lookup_backend.selected} · {selected.lookup_backend.scope.replaceAll('-', ' ')}</small></article>}
          {!selected.lookup_backend && selected.gpu_comparison && <article><span>GPU QUALIFICATION</span><strong>{selected.gpu_comparison.state.toUpperCase()}</strong><small>{selected.gpu_comparison.mismatches ?? '—'} mismatches · {typeof selected.gpu_comparison.performance?.probe_speedup === 'number' ? `${selected.gpu_comparison.performance.probe_speedup.toFixed(2)}× packed-probe speedup` : 'candidate timing unavailable'} · legacy dual run</small></article>}
        </div>
        <div className="hash-type-comparison">{hashTypes.map(row => <button key={row.hash_type} className={row.hash_type === activeType?.hash_type ? 'active' : ''} onClick={() => setSelectedHashType(row.hash_type)}><span>{row.hash_type.toUpperCase()}</span><strong>{row.multi_owner_values.toLocaleString()}</strong><small>multi-owner / {row.distinct_values.toLocaleString()} values</small><dl><div><dt>AMBIGUOUS</dt><dd>{observedPercent(row.multi_owner_fraction)}</dd></div><div><dt>OWNER LINKS</dt><dd>{row.ambiguous_owner_links.toLocaleString()}</dd></div><div><dt>MAX OWNERS</dt><dd>{row.maximum_distinct_owners}</dd></div><div><dt>RESOLVED BY COMPLETE</dt><dd>{row.complete_disambiguated_owner_signatures.toLocaleString()}</dd></div></dl></button>)}</div>
      </>}
    </section>

    {activeType && <HashNoisePopulationGraph row={activeType} />}

    {activeType && <section className="panel hash-population-panel"><header><h3>{activeType.hash_type} hash population</h3><span>PREVALENCE TAIL × CONTRIBUTING LIBRARIES</span></header><div className="hash-population-map"><HashPopulationTail rows={[activeType]} /><HashLibraryPopulation row={activeType} /></div></section>}

    {activeType && <section className="hdi-method-grid hash-drill-grid">
      <article className="panel hash-ambiguity-panel"><header><h3>{activeType.hash_type} hash ambiguity</h3><span>{activeType.top_ambiguous?.length ?? 0} VISIBLE</span></header><div>{activeType.top_ambiguous?.map(row => <details key={`${row.scope}-${row.language}-${row.value}`}><summary><code>{row.value}</code><strong>{row.distinct_owners} owners</strong><span>{row.reference_observations.toLocaleString()} observations</span><em>EXPAND</em></summary><section><p><span>OWNERS</span><strong>{row.owners.join(' · ')}</strong></p><p><span>COMPATIBILITY</span><strong>{row.scope} · {row.language}</strong></p><p><span>EXACT VARIANTS</span><strong>{row.exact_signature_variants.toLocaleString()}</strong></p><p><span>EXACT FP OBS.</span><strong>{row.exact_false_positive_observations.toLocaleString()}</strong></p></section></details>)}{!activeType.top_ambiguous?.length && <div className="operational-empty"><strong>No multi-owner values</strong><small>This hash type did not repeat across owners in the selected run.</small></div>}</div></article>
      <article className="panel hash-library-panel"><header><h3>Libraries carrying ambiguous {activeType.hash_type} hashes</h3><span>{activeType.libraries?.length ?? 0} OWNERS</span></header><div className="hash-library-head"><span>Library</span><span>Ambiguous</span><span>Values</span><span>Misses</span><span>Exact FP</span></div><div>{activeType.libraries?.map(row => <article key={row.owner}><strong>{row.owner}</strong><b>{observedPercent(row.ambiguous_fraction)}</b><span>{row.multi_owner_values.toLocaleString()} / {row.distinct_values.toLocaleString()}</span><span>{row.missed_observations.toLocaleString()}</span><span>{row.exact_false_positive_observations.toLocaleString()}</span></article>)}</div></article>
    </section>}
  </>;
}

export function HashDiscriminationView({ factory }: { factory: FactoryApiState }) {
  const hdi = factory.authority?.hash_discrimination;
  const ledger = factory.noisyHashes;
  const [draftStates, setDraftStates] = useState<Record<string, NoisyHashRow['disposition']>>({});
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [message, setMessage] = useState('');
  if (!hdi || !ledger) return <div className="view-stack"><ViewIntro kicker="HASH DISCRIMINATION" title="Hash discrimination" action={<span className="validation-state waiting">UNAVAILABLE</span>} /><PanelReadWarning factory={factory} endpoints={['authority', 'noisy-hashes', 'validation-observatory']} /><section className="panel"><div className="empty-state"><span>◇</span><strong>No HDI authority loaded</strong><p>Reconnect the local API or inspect validation/hash-discrimination.toml.</p></div></section></div>;
  const applyDecision = async (row: NoisyHashRow) => {
    const state = draftStates[row.signature_id] ?? row.disposition;
    const reason = reasons[row.signature_id] ?? '';
    if (!reason.trim()) return;
    setMessage(`Recording ${state} for ${row.signature_id}…`);
    try {
      await factory.decideNoisyHash(row.signature_id, state, reason.trim());
      setMessage(`Recorded ${state} as a reviewable TOML decision.`);
      setReasons(current => ({ ...current, [row.signature_id]: '' }));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Decision failed.');
    }
  };
  return <div className="view-stack noisy-hash-view hdi-view">
    <section className="hdi-page-bar"><h2>Hash discrimination</h2><div className="view-intro-actions"><span className={`validation-state ${hdi.readiness.ready_for_first_fit ? 'ready' : 'waiting'}`}>{hdi.readiness.ready_for_first_fit ? 'READY TO FIT' : hdi.corpus_index.generation ? 'EVIDENCE GROWING' : 'WAITING'}</span><button className="secondary-action" onClick={() => void factory.refresh()}>Refresh</button></div></section>
    <PanelReadWarning factory={factory} endpoints={['authority', 'noisy-hashes', 'validation-observatory']} />

    <ValidationObservatoryPanel factory={factory} />

    <section className="panel hdi-readiness-panel"><header><h3>Model readiness</h3><span className={`validation-state ${hdi.readiness.ready_for_first_fit ? 'ready' : 'waiting'}`}>{hdi.state.replaceAll('-', ' ')}</span></header><div className="hdi-headline-metrics"><article><span>C10 WIDTH</span><strong>{hdi.readiness.complete_library_families}/{hdi.readiness.required_library_families}</strong><small>complete library families</small></article><article><span>CORPUS INDEX</span><strong>{hdi.corpus_index.generation ? `G${hdi.corpus_index.generation.ordinal}` : '—'}</strong><small>{hdi.corpus_index.generation ? `${hdi.corpus_index.generation.owners} owners · ${hdi.corpus_index.generation.signatures.toLocaleString()} signatures` : 'awaiting first admitted batch'}</small></article><article><span>LANE GENERATIONS</span><strong>{hdi.readiness.materialized_lane_generations}</strong><small>occurrence-preserving corpora</small></article><article><span>RAW OBSERVATIONS</span><strong>{hdi.readiness.raw_observations.toLocaleString()}</strong><small>all-signature denominator</small></article><article><span>SCORED HASHES</span><strong>{hdiMeasure(hdi.summary.scored_signatures)}</strong><small>unavailable until first fit</small></article><article><span>VALIDATION</span><strong>{hdi.readiness.machine_validation_state === 'measured-complete' ? 'MEASURED' : '—'}</strong><small>{hdi.readiness.ecological_measured_cases} held-out cases</small></article><article><span>COLLISION LEDGER</span><strong>{hdi.summary.observed_collision_signatures}</strong><small>one input, not the model</small></article></div>{hdi.readiness.blockers.length > 0 && <div className="hdi-blockers"><strong>FIRST-FIT BLOCKERS</strong><div>{hdi.readiness.blockers.map(blocker => <span key={blocker}>! {blocker}</span>)}</div></div>}</section>

    <HashFormulaPanel hdi={hdi} />

    <section className="hdi-method-grid">
      <article className="panel hdi-repro-panel"><header><h3>Reproducibility</h3><code>{hdi.authority_sha256.slice(0, 16)}…</code></header><dl><div><dt>Algorithm</dt><dd>{hdi.reproducibility.algorithm_id}</dd></div><div><dt>Ordering</dt><dd>{hdi.reproducibility.deterministic_order}</dd></div><div><dt>Randomness</dt><dd>{hdi.reproducibility.randomness}</dd></div><div><dt>Arithmetic</dt><dd>{hdi.reproducibility.floating_point} · {hdi.reproducibility.rounding_decimal_places} decimals</dd></div><div><dt>Source pins</dt><dd>{hdi.reproducibility.source_digest_policy}</dd></div><div><dt>Publication</dt><dd>{hdi.reproducibility.generation_write_policy} · code revision required</dd></div></dl><footer>Manifest pins authority, corpus, reports, decisions and code revision.</footer></article>
      <article className="panel hdi-signal-panel"><header><h3>Inputs</h3><span>{hdi.signals.filter(signal => signal.required).length} REQUIRED</span></header><div>{hdi.signals.map(signal => <p key={signal.id}><span className={`hdi-signal-state ${signal.state === 'available' ? 'available' : 'waiting'}`}>{signal.state.replaceAll('-', ' ')}</span><strong>{signal.label}</strong><small>{signal.requirement.replaceAll('-', ' ')}{signal.required ? ' · required' : ' · later refinement'}</small></p>)}</div></article>
    </section>

    <section className="hdi-method-grid">
      <article className="panel hdi-treatment-panel"><header><h3>Treatment comparison</h3><span>4 ARMS</span></header><div>{hdi.treatments.map(treatment => <article key={treatment.id}><span>{treatment.id === 'unweighted-baseline' ? 'BASELINE' : 'EXPERIMENT'}</span><p><strong>{treatment.label}</strong><small>{treatment.mode.replaceAll('-', ' ')}</small></p><dl><div><dt>Precision</dt><dd>{hdiMeasure(treatment.precision)}</dd></div><div><dt>Recall</dt><dd>{hdiMeasure(treatment.recall)}</dd></div><div><dt>FPR</dt><dd>{hdiMeasure(treatment.false_positive_rate)}</dd></div><div><dt>Abstain</dt><dd>{hdiMeasure(treatment.abstention_rate)}</dd></div></dl></article>)}</div></article>
      <article className="panel hdi-generation-panel"><header><h3>Generations</h3><span>FORWARD EVALUATED</span></header><div>{hdi.generations.map(generation => <article key={generation.id}><span className={`hdi-generation-state ${generation.state}`}>{generation.state.replaceAll('-', ' ')}</span><p><strong>{generation.id}</strong><small>{generation.role.replaceAll('-', ' ')}</small></p><b>{generation.scored_signatures === null ? '—' : generation.scored_signatures.toLocaleString()}</b></article>)}</div><footer>Detection output pins the model generation; formula changes create a new version.</footer></article>
    </section>

    <section className="panel hdi-score-panel"><header><h3>Hash scores</h3><span>{hdi.scores.length} SCORED</span></header><div className="hdi-score-head"><span>Hash / compatible scope</span><span>Candidate owner</span><span>HDI</span><span>Noise risk</span><span>Confidence / reason</span></div><div className="hdi-score-list">{hdi.scores.map(score => <article key={score.score_id}><p><code>{score.signature}</code><small>{score.scope}</small></p><strong>{score.candidate_owner}</strong><b>{score.hdi.toFixed(1)}</b><b>{score.noise_risk.toFixed(1)}</b><p><strong>{score.evidence_sufficiency}</strong><small>{score.reason_category.replaceAll('-', ' ')}</small></p></article>)}{!hdi.scores.length && <div className="operational-empty"><strong>Scores unavailable</strong><small>C10 and candidate-contribution evidence are not complete.</small></div>}</div></section>

    <section className="panel noisy-summary-panel"><header><h3>Manual trust ledger</h3><code>{ledger.authority_path}</code></header><div className="noisy-summary-grid"><article><span>CANDIDATES</span><strong>{ledger.summary.candidate_noisy}</strong><small>at least one opposite-fold match</small></article><article><span>CONFIRMED NOISY</span><strong>{ledger.summary.confirmed_noisy}</strong><small>≥{ledger.classification.confirmed_min_collisions} observations in ≥{ledger.classification.confirmed_min_distinct_runs} runs</small></article><article><span>QUARANTINED</span><strong>{ledger.summary.quarantined}</strong><small>forward admission exclusion</small></article><article><span>REVIEWED SHARED</span><strong>{ledger.summary.reviewed_shared}</strong><small>useful but ambiguous</small></article><article><span>CLEARED</span><strong>{ledger.summary.cleared}</strong><small>reviewed false alarm</small></article></div><footer><strong>{ledger.summary.evidence_databases_scanned} machine evidence databases.</strong><span>Disposition changes require an explicit reason; published evidence remains immutable.</span></footer></section>
    {message && <div className="toast">{message}</div>}
    <section className="panel noisy-ledger-panel"><header><h3>Collision review</h3><span>{ledger.summary.returned_hashes} / {ledger.summary.observed_hashes} HASHES</span></header>{ledger.summary.hash_rows_truncated > 0 && <div className="inline-warning">Showing the {ledger.summary.returned_hashes} highest-priority review rows. {ledger.summary.hash_rows_truncated} further hashes remain preserved in the evidence database.</div>}<div className="noisy-hash-list">{ledger.hashes.map(row => <details key={row.signature_id}><summary><span className={`noisy-class ${row.classification}`}>{row.classification.replaceAll('-', ' ')}</span><code>{row.signature}</code><p><strong>{row.scope}</strong><small>{row.distinct_runs} runs · {row.collisions} collisions · {row.distinct_owners} owners · {row.sources.join(' + ')}</small></p><span className={`noisy-disposition ${row.disposition}`}>{row.disposition.replaceAll('-', ' ')}</span><em>EXPAND</em></summary><section><div className="noisy-owner-strip"><span>AFFECTED OWNERS</span><p>{row.owners.join(' · ')}</p></div><div className="noisy-decision-editor"><label><span>DISPOSITION</span><select value={draftStates[row.signature_id] ?? row.disposition} onChange={event => setDraftStates(current => ({ ...current, [row.signature_id]: event.target.value as NoisyHashRow['disposition'] }))}>{ledger.management.allowed_states.map(state => <option key={state} value={state}>{state.replaceAll('-', ' ')}</option>)}</select></label><label><span>REVIEW REASON</span><input value={reasons[row.signature_id] ?? ''} onChange={event => setReasons(current => ({ ...current, [row.signature_id]: event.target.value }))} maxLength={500} placeholder="Evidence-based reason required" /></label><button onClick={() => void applyDecision(row)} disabled={!reasons[row.signature_id]?.trim() || factory.busyAction === `noisy-hash:${row.signature_id}`}>Record TOML decision</button></div>{row.decision && <div className="noisy-current-decision"><strong>Current decision</strong><span>{row.decision.state} · {row.decision.reason} · {row.decision.reviewed_by} · {row.decision.reviewed_at}</span><code>{row.decision.path}</code></div>}<div className="noisy-evidence-head"><span>Run / source</span><span>Owner / function</span><span>Route / compiler / treatment</span><span>Evidence</span></div><div className="noisy-evidence-list">{row.evidence.map((evidence, index) => <article key={`${evidence.run_id}-${index}`}><div><strong>{evidence.run_id}</strong><small>{evidence.source}</small></div><div><strong>{evidence.owner}</strong><small>{evidence.function_id || evidence.library_id}</small></div><div><strong>{evidence.route_id}</strong><small>{evidence.compiler_id} · {evidence.treatment_id}</small></div><code>{evidence.evidence_path}</code></article>)}</div>{row.evidence_rows_truncated > 0 && <footer>{row.evidence_rows_truncated} additional evidence rows remain in the source reports.</footer>}</section></details>)}{!ledger.hashes.length && <div className="operational-empty"><strong>No collision evidence</strong><small>No collision-bearing validation reports are available.</small></div>}</div></section>
  </div>;
}
