'use client';

import { useState, type CSSProperties } from 'react';

const navItems = [
  ['01', 'Overview'],
  ['02', 'Planner'],
  ['03', 'Batches'],
  ['04', 'Toolchains'],
  ['05', 'Evidence'],
];

const workers = [
  {
    name: 'reference-host / host',
    detail: '2 slots · QEMU + local',
    state: 'Building',
    tone: 'running',
  },
  {
    name: 'reference-host / toolbx',
    detail: '1 slot · local',
    state: 'Ready',
    tone: 'ready',
  },
  {
    name: 'm1-max / native',
    detail: '1 slot · darwin arm64',
    state: 'Offline',
    tone: 'offline',
  },
];

const stages = [
  ['Acquire', '18 / 18', 100, 'complete'],
  ['Prepare', '18 / 18', 100, 'complete'],
  ['Compile', '11 / 18', 61, 'active'],
  ['Ghidra', '7 / 18', 39, 'active'],
  ['Seal', '5 / 18', 28, 'queued'],
];

export default function Home() {
  const [activeView, setActiveView] = useState('Overview');
  const [paused, setPaused] = useState(false);
  const viewTitles: Record<string, string> = {
    Overview: 'Good evening, Gray.',
    Planner: 'Resolve a governed build plan.',
    Batches: 'Track every batch and cell.',
    Toolchains: 'Worker capability coverage.',
    Evidence: 'Inspect outputs and provenance.',
    Automation: 'Bound unattended operation.',
    Activity: 'Follow the factory event stream.',
  };
  return (
    <main className="app-shell">
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
          <span className="pulse-dot" />
          <div>
            <strong>reference-host</strong>
            <span>controller online</span>
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
              {label === 'Batches' && <em>3</em>}
            </button>
          ))}
          <p className="nav-label secondary-label">Operations</p>
          <button className={activeView === 'Automation' ? 'nav-item active' : 'nav-item'} onClick={() => setActiveView('Automation')}>
            <span>06</span>
            Automation
            <i className="armed-dot" />
          </button>
          <button className={activeView === 'Activity' ? 'nav-item active' : 'nav-item'} onClick={() => setActiveView('Activity')}>
            <span>07</span>
            Activity
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="environment-card">
            <span className="environment-key">ENV</span>
            <div>
              <strong>Production</strong>
              <span>codex/post-unification</span>
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
          <div>
            <p className="eyebrow">FIDB FACTORY / {activeView.toUpperCase()}</p>
            <h1>{viewTitles[activeView]}</h1>
          </div>
          <div className="topbar-actions">
            <div className="sync-state">
              <span />
              Live · synced now
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
                <span className="status-pill running">NIGHT RUN ACTIVE</span>
                <span>Campaign 04</span>
              </div>
              <h2>Malware-relevant coverage baseline</h2>
              <p>18 build cells across 3 workers · QEMU default · local explicitly allowed</p>
            </div>
            <div className="campaign-progress">
              <div className="progress-ring" style={{ '--progress': '61%' } as CSSProperties}>
                <strong>61%</strong>
              </div>
              <div>
                <span>11 of 18 cells</span>
                <strong>04:18 remaining</strong>
              </div>
            </div>
            <div className="campaign-actions">
              <button className="ghost-button">Stop after cell</button>
              <button className={paused ? 'pause-button paused' : 'pause-button'} onClick={() => setPaused(!paused)}>
                {paused ? '▶  Resume scheduling' : 'Ⅱ  Pause scheduling'}
              </button>
            </div>
          </section>

          <section className="metrics-grid" aria-label="Campaign metrics">
            <article className="metric-card">
              <div className="metric-top"><span>QUEUE</span><b className="metric-symbol">≋</b></div>
              <strong>48</strong>
              <p><i className="up">↗ 12</i> since campaign start</p>
            </article>
            <article className="metric-card">
              <div className="metric-top"><span>WORKER SLOTS</span><b className="metric-symbol">⌘</b></div>
              <strong>3 <small>/ 4</small></strong>
              <p><i className="healthy">●</i> 75% utilised</p>
            </article>
            <article className="metric-card">
              <div className="metric-top"><span>SUCCESS RATE</span><b className="metric-symbol">⌁</b></div>
              <strong>92.4<small>%</small></strong>
              <p><i className="up">↗ 2.1%</i> over 7 days</p>
            </article>
            <article className="metric-card warning-card">
              <div className="metric-top"><span>REQUIREMENTS</span><b className="metric-symbol">!</b></div>
              <strong>2</strong>
              <p><i className="warning">●</i> unmet toolchains</p>
            </article>
          </section>

          <section className="dashboard-grid">
            <article className="panel pipeline-panel">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">ACTIVE BATCH</p>
                  <h3>mirai-baseline / batch-007</h3>
                </div>
                <button className="text-button" onClick={() => setActiveView('Batches')}>View batch&nbsp; →</button>
              </div>
              <div className="pipeline-list">
                {stages.map(([label, count, progress, state]) => (
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
                  <span>CURRENT CELL</span>
                  <strong>mirai / powerpc-e500mc / source</strong>
                  <small>uclibc 0.9.30.1 · QEMU · mirai_bot_gcc</small>
                </div>
                <div className="cell-time">
                  <span>18:42</span>
                  <small>elapsed</small>
                </div>
              </div>
            </article>

            <article className="panel workers-panel">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">EXECUTION</p>
                  <h3>Worker pool</h3>
                </div>
                <button className="round-add" aria-label="Add worker">+</button>
              </div>
              <div className="worker-list">
                {workers.map((worker) => (
                  <div className="worker-row" key={worker.name}>
                    <span className={`worker-glyph ${worker.tone}`}>⌬</span>
                    <div>
                      <strong>{worker.name}</strong>
                      <small>{worker.detail}</small>
                    </div>
                    <span className={`worker-state ${worker.tone}`}>{worker.state}</span>
                  </div>
                ))}
              </div>
              <button className="full-width-button" onClick={() => setActiveView('Toolchains')}>Manage workers</button>
            </article>

            <article className="panel requirement-panel">
              <div className="alert-icon">!</div>
              <div className="alert-copy">
                <p className="panel-kicker">ACTION REQUIRED</p>
                <h3>2 cells have no eligible worker</h3>
                <p>The pinned MIPS toolchain is cached but not target-probed in any active environment.</p>
                <div className="alert-tags"><span>mips</span><span>uclibc</span><span>local</span></div>
              </div>
              <button className="amber-button" onClick={() => setActiveView('Toolchains')}>Review requirements</button>
            </article>

            <article className="panel activity-panel">
              <div className="panel-header">
                <div>
                  <p className="panel-kicker">EVENT STREAM</p>
                  <h3>Recent activity</h3>
                </div>
                <button className="text-button" onClick={() => setActiveView('Activity')}>Open logs&nbsp; →</button>
              </div>
              <div className="event-list">
                <div className="event-row"><time>22:41:08</time><span className="event-dot success"/><p><strong>cell.completed</strong> powerpc-e500mc · manifest sealed</p></div>
                <div className="event-row"><time>22:40:51</time><span className="event-dot info"/><p><strong>stage.started</strong> Ghidra population · 329 functions</p></div>
                <div className="event-row"><time>22:39:17</time><span className="event-dot warning"/><p><strong>requirement.blocked</strong> mips-uclibc · no target probe</p></div>
                <div className="event-row"><time>22:38:03</time><span className="event-dot success"/><p><strong>toolchain.verified</strong> powerpc-buildroot-linux-uclibc</p></div>
              </div>
            </article>
          </section>
          </> : <SecondaryView view={activeView} />}
        </div>
      </section>
    </main>
  );
}

function SecondaryView({ view }: { view: string }) {
  if (view === 'Planner') return <PlannerView />;
  if (view === 'Batches') return <BatchesView />;
  if (view === 'Toolchains') return <ToolchainsView />;
  if (view === 'Evidence') return <EvidenceView />;
  if (view === 'Automation') return <AutomationView />;
  return <ActivityView />;
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

function PlannerView() {
  const [executor, setExecutor] = useState('qemu');
  const [workflow, setWorkflow] = useState('hunt');
  const [resolved, setResolved] = useState(false);
  return (
    <div className="view-stack">
      <ViewIntro kicker="BUILD PLANNER" title="Resolve before execution" copy="Every selection becomes an immutable CLI plan. Commands and compiler flags remain derived and read-only." action={<button className="primary-action" onClick={() => setResolved(true)}>Resolve plan</button>} />
      <div className="planner-layout">
        <section className="panel form-panel">
          <div className="section-title"><span>01</span><div><strong>Work request</strong><small>Choose the existing CLI workflow.</small></div></div>
          <label className="field-label">Workflow</label>
          <div className="segmented-control">
            {['native', 'hunt', 'malware'].map(item => <button key={item} onClick={() => setWorkflow(item)} className={workflow === item ? 'selected' : ''}>{item}</button>)}
          </div>
          <label className="field-label" htmlFor="target">Target or recipe</label>
          <div className="input-shell"><span>⌁</span><input id="target" defaultValue={workflow === 'hunt' ? '/samples/router-busybox' : 'mirai-original-bot'} /></div>
          <label className="field-label">Executor</label>
          <div className="executor-choice">
            <button className={executor === 'qemu' ? 'selected' : ''} onClick={() => setExecutor('qemu')}><span>Q</span><div><strong>QEMU</strong><small>Default isolation boundary</small></div><i>recommended</i></button>
            <button className={executor === 'local' ? 'selected local' : ''} onClick={() => setExecutor('local')}><span>L</span><div><strong>Local</strong><small>Invoking Linux environment</small></div></button>
          </div>
          {executor === 'local' && <div className="inline-warning">Local is explicit opt-in and does not provide the QEMU isolation boundary.</div>}
          <div className="section-divider" />
          <div className="section-title"><span>02</span><div><strong>Campaign policy</strong><small>Bound where the plan may run.</small></div></div>
          <div className="two-fields"><label><span>Maximum cells</span><input defaultValue="18" /></label><label><span>Priority</span><select defaultValue="normal"><option>normal</option><option>high</option><option>background</option></select></label></div>
        </section>

        <section className="panel resolved-panel">
          <div className="panel-header"><div><p className="panel-kicker">RESOLVED PLAN</p><h3>{resolved ? 'plan:7e4a2f68c913' : 'Preview'}</h3></div><span className={`plan-state ${resolved ? 'ready' : ''}`}>{resolved ? 'READY' : 'NOT RESOLVED'}</span></div>
          <div className="resolution-summary">
            <div><span>WORKFLOW</span><strong>{workflow}</strong></div><div><span>EXECUTOR</span><strong>{executor}</strong></div><div><span>CELLS</span><strong>{resolved ? '18' : '—'}</strong></div><div><span>ETA</span><strong>{resolved ? '06:24–07:10' : '—'}</strong></div>
          </div>
          <div className="resolved-table">
            <div className="table-head"><span>Cell</span><span>Toolchain</span><span>Worker coverage</span><span>State</span></div>
            {(resolved ? [
              ['powerpc-e500mc', 'bootlin 2017.05', '2 workers', 'ready'],
              ['mips32-big', 'fwl uclibc', '0 workers', 'blocked'],
              ['armv5l', 'bootlin 2020.08', '1 worker', 'ready'],
              ['x86-i686', 'bootlin stable', '2 workers', 'ready'],
            ] : []).map(row => <div className="table-row" key={row[0]}><strong>{row[0]}</strong><span>{row[1]}</span><span>{row[2]}</span><em className={row[3]}>{row[3]}</em></div>)}
            {!resolved && <div className="empty-state"><span>◇</span><strong>No plan resolved yet</strong><p>Resolve the selections to preview exact cells, pins, requirements, and eligible workers.</p></div>}
          </div>
          {resolved && <div className="plan-footer"><div><span className="event-dot warning" /><p><strong>1 blocking requirement</strong><small>MIPS target probe required before queueing.</small></p></div><button disabled>Queue plan</button></div>}
        </section>
      </div>
    </div>
  );
}

function BatchesView() {
  const batches = [
    ['batch-007', 'mirai-baseline', 'Running', '11 / 18', 61, 'reference-host / host', 'QEMU', '04:18'],
    ['batch-006', 'uclibc-hunt', 'Blocked', '4 / 8', 50, '—', 'Local', '—'],
    ['batch-005', 'native-smoke', 'Complete', '12 / 12', 100, 'reference-host / toolbx', 'Native', '00:00'],
    ['batch-004', 'busybox-targets', 'Queued', '0 / 24', 0, '—', 'QEMU', '08:40'],
    ['batch-003', 'archive-candidates', 'Complete', '40 / 40', 100, 'reference-host / host', 'Archive', '00:00'],
  ];
  return <div className="view-stack">
    <ViewIntro kicker="BATCH OPERATIONS" title="Queue and execution ledger" copy="Each batch retains its immutable plan, attempts, worker leases, events, reports, and resulting artifacts." action={<button className="primary-action">+ New batch</button>} />
    <section className="panel data-panel">
      <div className="filterbar"><button className="filter active">All <span>5</span></button><button className="filter">Running <span>1</span></button><button className="filter">Blocked <span>1</span></button><button className="filter">Complete <span>2</span></button><div className="filter-search">⌕&nbsp; Filter batches</div></div>
      <div className="batch-table">
        <div className="batch-head"><span>Batch</span><span>Status</span><span>Progress</span><span>Worker</span><span>Route</span><span>ETA</span><span /></div>
        {batches.map(batch => <div className="batch-row" key={batch[0] as string}>
          <div><strong>{batch[0]}</strong><small>{batch[1]}</small></div><span className={`batch-status ${(batch[2] as string).toLowerCase()}`}>{batch[2]}</span>
          <div className="table-progress"><div><span style={{width: `${batch[4]}%`}} /></div><small>{batch[3]}</small></div><span>{batch[5]}</span><code>{batch[6]}</code><strong className="eta">{batch[7]}</strong><button>•••</button>
        </div>)}
      </div>
    </section>
  </div>;
}

function ToolchainsView() {
  const [message, setMessage] = useState('');
  const rows = [
    ['powerpc-e500mc', 'uClibc 0.9.30.1', '32-bit · BE', 'E2 target-probed', 'ready', '2 / 2', 'Verify'],
    ['mips32-big', 'uClibc 0.9.30.1', '32-bit · BE', 'E1 identified', 'warning', '0 / 2', 'Probe'],
    ['armv5l', 'uClibc stable', '32-bit · LE', 'E2 target-probed', 'ready', '1 / 2', 'Verify'],
    ['x86-i686', 'uClibc stable', '32-bit · LE', 'E2 target-probed', 'ready', '2 / 2', 'Verify'],
    ['m68k-68xxx', 'uClibc legacy', '32-bit · BE', 'Archive cached', 'cold', '0 / 2', 'Prepare'],
  ];
  return <div className="view-stack">
    <ViewIntro kicker="CAPABILITY REGISTRY" title="Toolchain coverage by worker" copy="Readiness is evidence for an exact toolchain, target ABI, executor, and worker environment—not an installed yes/no flag." action={<button className="primary-action" onClick={() => setMessage('Inventory refresh queued on 2 active workers.')}>Refresh inventory</button>} />
    {message && <div className="toast" role="status">✓ {message}</div>}
    <section className="toolchain-summary">
      <article><span>REGISTRY ROWS</span><strong>41</strong><small>40 archive · 1 source</small></article><article><span>READY CELLS</span><strong>38</strong><small>92.7% coverage</small></article><article className="warn"><span>UNMET</span><strong>2</strong><small>target probes required</small></article><article><span>ACTIVE WORKERS</span><strong>2</strong><small>3 execution slots</small></article>
    </section>
    <section className="panel data-panel">
      <div className="filterbar"><button className="filter active">All variants</button><button className="filter">Source capable</button><button className="filter">Unmet</button><div className="filter-search">⌕&nbsp; Search variant or ABI</div></div>
      <div className="toolchain-table">
        <div className="toolchain-head"><span>Variant</span><span>Family</span><span>Target ABI</span><span>Evidence</span><span>Workers</span><span>Action</span></div>
        {rows.map(row => <div className="toolchain-row" key={row[0]}><div><span className={`cap-dot ${row[4]}`} /><strong>{row[0]}</strong></div><span>{row[1]}</span><code>{row[2]}</code><span className={`evidence-badge ${row[4]}`}>{row[3]}</span><strong>{row[5]}</strong><button onClick={() => setMessage(`${row[6]} queued for ${row[0]}.`)}>{row[6]}</button></div>)}
      </div>
    </section>
  </div>;
}

function EvidenceView() {
  return <div className="view-stack">
    <ViewIntro kicker="PROVENANCE & OUTPUTS" title="Evidence remains readable files" copy="Inspect manifests, reports, normalized FID results, checksums, and the exact CLI invocation behind each result." action={<button className="secondary-action">Export index</button>} />
    <div className="evidence-layout">
      <section className="panel artifact-list"><div className="panel-header"><div><p className="panel-kicker">LATEST OUTPUTS</p><h3>Sealed artifacts</h3></div><span className="plan-state ready">5 NEW</span></div>
        {[
          ['library.fidb', 'FID database', '4.8 MB', '7e4a2f68…c913'],
          ['library.fidbf', 'Raw FID export', '3.1 MB', '1f8823c0…a51d'],
          ['manifest.json', 'Build provenance', '18 KB', '409e87d1…084c'],
          ['matches.json', 'Normalized matches', '242 KB', 'c7a42d51…e02b'],
          ['stderr.log', 'Bounded execution log', '86 KB', '69ee0b34…72af'],
        ].map(file => <button className="artifact-row" key={file[0]}><span className="file-glyph">{file[0].split('.').pop()?.toUpperCase()}</span><div><strong>{file[0]}</strong><small>{file[1]}</small></div><span>{file[2]}</span><code>{file[3]}</code><b>→</b></button>)}
      </section>
      <section className="panel provenance-card"><div className="panel-header"><div><p className="panel-kicker">SELECTED CELL</p><h3>powerpc-e500mc-source</h3></div><span className="worker-state ready">Sealed</span></div>
        <dl><div><dt>Plan digest</dt><dd>7e4a2f68c913</dd></div><div><dt>Executor</dt><dd>qemu</dd></div><div><dt>Adapter</dt><dd>mirai_bot_gcc</dd></div><div><dt>Toolchain</dt><dd>Bootlin 2017.05</dd></div><div><dt>Target</dt><dd>PowerPC 32-bit BE</dd></div><div><dt>Worker</dt><dd>reference-host / host</dd></div><div><dt>Compiler SHA-256</dt><dd className="digest">bb1e3a8f…0419</dd></div><div><dt>Binary SHA-256</dt><dd className="digest">1cbed3fe…15e</dd></div></dl>
        <div className="cli-preview"><span>CLI INVOCATION</span><code>fidb-poc worker execute --plan 7e4a2f68c913 --cell powerpc-e500mc-source</code></div>
      </section>
    </div>
  </div>;
}

function AutomationView() {
  const [armed, setArmed] = useState(true);
  const [mode, setMode] = useState('Night / factory');
  return <div className="view-stack">
    <ViewIntro kicker="UNATTENDED OPERATION" title="Campaign automation" copy="The clock defines the maximum budget. Worker pressure, disk leases, and operator inhibits can only reduce it." action={<button className={armed ? 'danger-action' : 'primary-action'} onClick={() => setArmed(!armed)}>{armed ? 'Disarm campaign' : 'Arm campaign'}</button>} />
    <div className="automation-layout">
      <section className="panel automation-form">
        <div className="panel-header"><div><p className="panel-kicker">ACTIVE POLICY</p><h3>overnight-baseline / v4</h3></div><span className={`plan-state ${armed ? 'ready' : ''}`}>{armed ? 'ARMED' : 'INACTIVE'}</span></div>
        <div className="policy-body">
          <label className="field-label">Operating mode</label><div className="mode-grid">{['Day / shared', 'Night / factory', 'Away', 'Inhibit'].map(item => <button key={item} onClick={() => setMode(item)} className={mode === item ? 'selected' : ''}><span>{item.split(' / ')[0]}</span><small>{item.split(' / ')[1] || (item === 'Away' ? 'explicit expiry' : 'no dispatch')}</small></button>)}</div>
          <div className="section-divider" />
          <div className="two-fields"><label><span>Start window</span><input type="time" defaultValue="22:00" /></label><label><span>Stop scheduling</span><input type="time" defaultValue="06:15" /></label></div>
          <div className="two-fields"><label><span>Maximum workers</span><input type="number" defaultValue="3" /></label><label><span>Retry ceiling</span><input type="number" defaultValue="1" /></label></div>
          <div className="toggle-list">
            <label><div><strong>QEMU default</strong><small>Local still requires explicit cell authorization.</small></div><input type="checkbox" defaultChecked /></label>
            <label><div><strong>Stop after blocking integrity alert</strong><small>Digest, compiler identity, or ABI mismatch.</small></div><input type="checkbox" defaultChecked /></label>
            <label><div><strong>Prepare pinned requirements</strong><small>Only during the configured network window.</small></div><input type="checkbox" defaultChecked /></label>
          </div>
        </div>
      </section>
      <aside className="automation-side">
        <section className="panel safety-card"><p className="panel-kicker">RESOURCE ENVELOPE</p><h3>Host safety</h3><div className="resource-line"><span>CPU ceiling</span><strong>70%</strong></div><div className="resource-meter"><span style={{width: '70%'}} /></div><div className="resource-line"><span>Memory reserve</span><strong>24 GB</strong></div><div className="resource-meter memory"><span style={{width: '42%'}} /></div><div className="resource-line"><span>Minimum free disk</span><strong>180 GB</strong></div><div className="resource-meter disk"><span style={{width: '58%'}} /></div></section>
        <section className="panel preflight-card"><p className="panel-kicker">PREFLIGHT</p><h3>Ready with warnings</h3><ul><li className="ok">2 active workers responding</li><li className="ok">QEMU route available</li><li className="warn">2 unmet MIPS requirements</li><li className="ok">412 GB free after leases</li></ul><button>Review immutable plan</button></section>
      </aside>
    </div>
  </div>;
}

function ActivityView() {
  const events = [
    ['22:41:08.412', 'cell.completed', 'powerpc-e500mc · manifest sealed', 'success'],
    ['22:40:51.028', 'stage.started', 'Ghidra population · 329 functions', 'info'],
    ['22:39:17.590', 'requirement.blocked', 'mips-uclibc · no target probe', 'warning'],
    ['22:38:03.114', 'toolchain.verified', 'powerpc-buildroot-linux-uclibc', 'success'],
    ['22:37:46.881', 'worker.heartbeat', 'reference-host/toolbx · 1 slot available', 'info'],
    ['22:35:20.447', 'stage.completed', 'compile · binary sha256 1cbed3fe…', 'success'],
    ['22:34:59.102', 'resource.lease', 'scratch 3.0 GB · expires 23:22', 'info'],
    ['22:32:41.777', 'cell.started', 'mirai / powerpc-e500mc / source', 'info'],
  ];
  return <div className="view-stack"><ViewIntro kicker="FACTORY TELEMETRY" title="Activity stream" copy="Structured CLI events are retained by run and forwarded live. Human logs remain separate on stderr." action={<button className="secondary-action">Download JSONL</button>} />
    <section className="panel terminal-panel"><div className="terminal-toolbar"><div><span /><span /><span /></div><code>campaign-04 / events.jsonl</code><button>Live tail ●</button></div><div className="terminal-events">{events.map(event => <div key={event[0]}><time>{event[0]}</time><span className={`event-dot ${event[3]}`} /><strong>{event[1]}</strong><p>{event[2]}</p></div>)}</div></section>
  </div>;
}
