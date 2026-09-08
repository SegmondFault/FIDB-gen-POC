'use client';

import type { CSSProperties } from 'react';

import { eventDetail, eventTime, eventTone, externalWorkerDisplay } from './coordinator-presenters';
import { formatStartedAt, stageLabel } from './formatters';
import type { FactoryApiState } from './panel-primitives';
import type { BatchRow } from './view-models';

export function OverviewView({
  factory,
  batches,
  navigateTo,
}: {
  factory: FactoryApiState;
  batches: BatchRow[];
  navigateTo: (view: string) => void;
}) {
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

  return <>
          <section className="campaign-banner">
            <div className="campaign-main">
              <div className="campaign-kicker">
                <span className={`status-pill ${factory.snapshot?.armed ? 'active' : 'queued'}`}>QUEUE {factory.snapshot?.status.toUpperCase() ?? 'UNKNOWN'}</span>
                <span>plans/priority-queue.toml</span>
              </div>
              <h2>Local library production queue</h2>
              <p>{totalJobs} typed jobs across {batches.length} batches · native and explicit local cross-builds · QEMU excluded</p>
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
              <button className="pause-button" onClick={() => navigateTo('Automation')}>Review automation</button>
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
                  <h3>{batches[0]?.name ?? 'No batch'} / {batches[0]?.id ?? '—'}</h3>
                </div>
                <button className="text-button" onClick={() => navigateTo('Batches')}>View batch&nbsp; →</button>
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
              </div>
              <div className="worker-list">
                {factory.capabilities ? [{
                  name: `${factory.capabilities.host.system}/${factory.capabilities.host.machine} · library-local`,
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
              <button className="full-width-button" onClick={() => navigateTo('Targets & toolchains')}>Inspect targets</button>
            </article>

            <article className="panel requirement-panel">
              <div className="alert-icon">!</div>
              <div className="alert-copy">
                <p className="panel-kicker">ACTION REQUIRED</p>
                <h3>{factory.connection === 'live' ? (factory.capabilities?.analysis.ready ? 'Library pool is visible' : 'Worker environment needs configuration') : 'Coordinator API unavailable'}</h3>
                <p>{factory.connection === 'live' ? `${pool?.ready_now ?? 0} jobs are ready immediately; ${pool?.runnable_with_pinned_acquisition ?? 0} can run after pinned acquisition. ${factory.capabilities?.analysis.ghidra.state === 'installed-unconfigured' ? 'Ghidra is installed but GHIDRA_HEADLESS is not configured for the API/worker service.' : ''}` : (factory.error ?? 'Start the loopback API service to read the durable ledger and toolchain inventory.')}</p>
                <div className="alert-tags"><span>library-local</span><span>max {factory.snapshot?.max_workers ?? 2}</span><span>{factory.snapshot?.performance_profile?.id ?? 'profile unbound'}</span><span>no QEMU</span></div>
              </div>
              <button className="amber-button" onClick={() => navigateTo('Automation')}>Review automation</button>
            </article>

            <article className="panel activity-panel">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">LEDGER ACTIVITY</p>
                  <h3>{factory.connection === 'live' ? 'Latest durable events' : 'Waiting for coordinator'}</h3>
                </div>
                <button className="text-button" onClick={() => navigateTo('Activity')}>Open logs&nbsp; →</button>
              </div>
              <div className="event-list">
                {latestEvents.map(event => <div className="event-row" key={event.event_id}><time>{eventTime(event)}</time><span className={`event-dot ${eventTone(event)}`}/><p><strong>{event.event_type}</strong> {eventDetail(event)}</p></div>)}
                {!latestEvents.length && <div className="empty-state compact"><span>◇</span><strong>No live ledger events</strong><p>Synchronizing the queue will create the first durable event.</p></div>}
              </div>
            </article>
          </section>
  </>;
}
