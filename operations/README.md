# Local library worker pool

These inactive user-service templates expose the loopback coordinator API and
run only the repository's native and explicit local cross-build library queue.
They are not for QEMU cells or malware work.  Nothing in this directory
installs, enables, arms, or starts an API or worker.

Reusable units resolve the account home through systemd's `%h` specifier and
expect the checkout at `%h/Projects/circl/FIDB-POC-unified`. Moving the project
to a dedicated Unix account therefore requires moving that tree, rebuilding
its environment and reinstalling the reviewed user units; no username is
embedded in the shared definitions.

On `reference-host`, the first native commissioning run installed these templates
for `fidb-operator`, completed zlib and bzip2, then paused and disarmed the queue.
The commissioning record says the two worker instances were disabled after
the drain and the loopback API and production panel were left enabled for
inspection. Verify their current state with `systemctl --user status`: the
user does not have lingering enabled, so a final logout can stop them. This
dated record does not turn the repository files into an installer and does not
imply that later checkout changes reached the installed copies.

## Operational campaigns

`operations/campaigns.toml` is the reviewed registry of operational campaign
slices. Each configured row binds exactly one queue authority to one durable
ledger. The default remains the current non-Apple C campaign and therefore
continues to use the existing `plans/priority-queue.toml` and
`var/fidb-coordinator/ledger.sqlite3` evidence.

Inspect the registry from the console:

```sh
.venv/bin/fidb-poc campaigns status --project-root .
```

Select a different configured, disarmed campaign:

```sh
.venv/bin/fidb-poc campaigns select CAMPAIGN_ID --project-root .
```

The same control is available on **Operations → Automation**. Selection writes
only `var/fidb-campaigns/active.toml`, which is local TOML state ignored by Git.
It does not alter, arm, synchronize or execute the target queue. A switch is
refused when the current ledger is armed or has live leases/running jobs, when
the target is only planned, or when the target queue authority is armed.

After selecting, synchronize the selected queue and start or restart worker
services. Workers resolve the campaign when their process starts; they never
hot-switch a running JVM between ledgers. The coordinator API resolves the
active binding per request, so the control panel follows the selection without
mixing event cursors or cached ledger projections.

The Apple C80 slice is intentionally `planned`. Materializing its queue on the
M1 Max is a later reviewed transition, not something campaign selection may
invent. Both Apple and non-Apple slices share the parent campaign identity but
retain different queue and ledger authorities.

The host has 16 physical cores/32 hardware threads, and each reviewed build
adapter may use four make jobs while every worker embeds one reusable Ghidra
JVM. The queue binds `reference-host-94g-balanced`: twenty active leases, four build
jobs per cell and a 4 GiB JVM heap ceiling. The twenty units named by
`fidb-library-local-workers.target` supply exactly that measured concurrency;
the queue rejects a `max_workers` value which drifts from the named profile. An
`auto` profile is resolved from physical cores, SMT siblings and OS-visible RAM
at queue load; its effective settings and host facts are retained in coordinator
state, and a different resolved worker count also fails closed.
Do not interpret 32 hardware threads as permission to exceed the qualified
twenty-worker envelope. That value is a coordinator ceiling, not a requirement
to start every service instance. The 1,129-object OpenSSL Android recovery used
14 active workers after its isolated 2,048-task canary measured about 5.43 GiB;
twenty simultaneous copies of that observed worst-cell footprint would exceed
94 GiB before host overhead.

## Before activation

The queue must remain library-only: resolved cells must have `kind = "native"`,
`kind = "source-library"` with `executor = "local"`, or
`kind = "archive-library"` with `executor = "archive-local"`. Do not add a
malware batch or a QEMU route to the queue
used by these units.  The worker unit also passes `--pool library-local`, so it
must fail closed if a future queue attempts to offer either kind of work.
Inspect the complete resolution while it is still disarmed:

```sh
cd "$HOME/Projects/circl/FIDB-POC-unified"
.venv/bin/fidb-poc queue sync --campaign-registry operations/campaigns.toml --full
.venv/bin/fidb-poc queue status --campaign-registry operations/campaigns.toml --full
.venv/bin/fidb-poc queue resolve-preflight --campaign-registry operations/campaigns.toml
```

`resolve-preflight` re-resolves every exact active ledger cell through the same
reviewed width, recipe and toolchain authorities used by execution. It performs
no compilation, starts no JVM, and writes no queue transition. Do not arm a
campaign unless it reports every active job as passed; `--batch ID` may be
repeated when checking a deliberately bounded subset.

Do not recover a failed campaign with SQLite updates. Keep it disarmed and
paused and verify that no lease is live, then use the guarded transition. No
different batch may be admitted; the selected failed batch may remain admitted
so its untouched and recovered cells retain their execution-block boundary:

```sh
.venv/bin/fidb-poc queue requeue-failed \
  --state var/fidb-coordinator/ledger.sqlite3 \
  --batch BATCH_ID --expected-count COUNT \
  --reason "canonical authority repair verified by canary"
```

The command aborts on any state or count drift. It retains attempts, stage
spans and prior errors in their immutable historical records, clears only the
current job's terminal error fields, and appends auditable job and batch
events. Inspect the returned job-ID digest before rearming.

An `OutOfMemoryError` saying `unable to create native thread` is not proof that
the 4 GiB Java heap or host RAM is exhausted. Compare the worker cgroup's
`TasksCurrent` with `TasksMax`. OpenSSL Android ARM64/O0 analysis imported 1,129
objects, crossed 1,100 observed tasks and failed under both the former 512 and
1,024-task ceilings. The isolated 2,048-task canary completed and sealed in
458.379 seconds. `MemoryHigh=6G` and `MemoryMax=8G` retain the memory guardrail.

Confirm that `/opt/ghidra/support/analyzeHeadless`, Java 21, the native route
tools, required pinned source/toolchain archives or network access, and ample
disk space are available. The example environment limits each JVM to a 4 GiB
heap and four visible processors. The queue worker validates that inherited
heap policy against its named performance profile and applies the profile's
four nested build jobs. The service adds a 6 GiB soft memory limit, an 8 GiB
hard limit, and a four-CPU quota.

The units deliberately do not name `network.target` or
`network-online.target`: those are system-manager targets and do not exist in
the `fidb-operator` user manager.  Before starting workers that may acquire an
input, check connectivity explicitly (for example with
`/usr/bin/nm-online -q --timeout=60`).  This first native-only commissioning
run uses already reviewed public source URLs. Managed acquisition has bounded
timeouts, checksum verification, retry and a content-addressed cache. The queue
worker also enforces the TOML admission schedule, durable retry backoff and
claim-time memory/disk/load/temperature gates. Authority-resolution failures
are normalized by stage and exception type; five terminal failures in the same
class and active batch pause the coordinator and append a
`queue.circuit-opened` event. Already leased cells retain their normal fences,
but no further cells are claimed until an operator has inspected the evidence
and explicitly resumes the queue.

The reviewed schedule admits ordered short chunks between 00:00 and 05:30
Europe/Luxembourg. With `finish_started_batch = true`, 05:30 closes admission
for the night but does not kill a cell or strand the rest of that batch:
workers keep claiming from the durable active-batch identity until it drains.
While the window remains open, `chain_batches = true` admits the next ordered
chunk; after 05:30 it waits for the next window. Worker services must already be
running for automatic admission; their polling loops sleep harmlessly while
there is no active or admissible block.

Inspect that decision without mutating the ledger:

```sh
.venv/bin/fidb-poc queue preflight --queue plans/priority-queue.toml
```

The command returns nonzero while the queue is disarmed, outside its claim
window, or blocked by a resource threshold. The control panel reads the same
evaluation from the loopback API rather than inventing a second policy.

An operator may bypass only the clock and admit the next batch manually:

```sh
.venv/bin/fidb-poc queue start-block --queue plans/priority-queue.toml
```

This fails while the TOML queue is disarmed, writes a `batch.admitted` event,
and starts no subprocess itself. Existing workers then drain that one block
under the normal pool, lease, retry and resource rules.

## Deliberately manual installation

Run these commands only after reviewing the paths and unit contents.  They are
instructions, not an installation script:

```sh
install -d -m 0755 "$HOME/.config/systemd/user" "$HOME/.config/fidb-factory"
install -m 0644 operations/fidb-coordinator-api.service "$HOME/.config/systemd/user/"
install -m 0644 operations/fidb-control-panel.service "$HOME/.config/systemd/user/"
install -m 0644 operations/fidb-library-local-worker@.service "$HOME/.config/systemd/user/"
install -m 0644 operations/fidb-library-local-workers.target "$HOME/.config/systemd/user/"
install -m 0644 operations/fidb-machine-validation-hash-analysis.service "$HOME/.config/systemd/user/"
install -m 0644 operations/fidb-machine-validation-hash-analysis-nightly.timer "$HOME/.config/systemd/user/"
install -m 0600 operations/library-local-worker.env.example "$HOME/.config/fidb-factory/library-local-worker.env"
systemctl --user daemon-reload
```

The recurring hash-analysis timer admits only the latest complete full
validation run without a current single-hash report. It fires at 00:00; the
service rechecks the TOML-defined window and exits without work outside it.
Enable it with:

```sh
systemctl --user enable --now fidb-machine-validation-hash-analysis-nightly.timer
```

Passed one-off timers and their campaign-specific service chain are retained
under [`operations/history/`](history/README.md). They are provenance, not
installable current configuration.

Review the copied environment file.  The API reuses it rather than introducing
a second operator environment.  Starting the API is safe while the queue is
disarmed: API synchronization, inspection, pause, and resume do not change the
TOML `armed` value and the API never claims a job.

Start the loopback API manually and verify it from `reference-host`:

```sh
systemctl --user enable --now fidb-coordinator-api.service
systemctl --user status fidb-coordinator-api.service
curl --fail --silent http://127.0.0.1:8765/api/v1/health
```

The unit spells out `--bind 127.0.0.1 --port 8765`.  Do not change that to a
wildcard or Tailscale address.  The API is not intended to be opened directly
from the Mac or another machine.

After `npm run build` succeeds in `control-panel`, start the production panel
and verify its same-origin proxy:

```sh
systemctl --user enable --now fidb-control-panel.service
systemctl --user status fidb-control-panel.service
curl --fail --silent http://127.0.0.1:3001/api/fidb/health
```

The shared unit binds to loopback by default and injects the loopback API origin
server-side. To expose the panel on a private network, add a reviewed user-unit
drop-in that overrides `FIDB_CONTROL_PANEL_BIND` with the host's private address.
Do not broaden it to an all-interface listener.

## Tailscale control-panel flow

The control panel and its server-side proxy run on `reference-host`.  Set the
control-panel server's private environment to
`FIDB_API_ORIGIN=http://127.0.0.1:8765`; this is already the documented default
in `control-panel/.env.example`.  The request path is:

```text
Mac browser
  -> http://<reference-host-tailscale-address>:3001
  -> same-origin /api/fidb/* route in the control-panel server
  -> http://127.0.0.1:8765/api/v1/* on reference-host
  -> var/fidb-coordinator/ledger.sqlite3
```

Loopback belongs to the machine running the control-panel server, not the Mac.
The browser therefore sees one Tailscale-served origin and never receives a
direct coordinator address.  The proxy accepts only its fixed API route set,
requires same-origin browser mutations, and forwards server-side over loopback;
the Python API needs no cross-origin allowance for this flow.

The GUI can synchronize, inspect, pause, and resume the coordinator through
that proxy. It can also resolve a generated plan against the authoritative
catalogs and save it under `plans/drafts` with conflict detection. Saving a
draft does not enqueue or execute it. The GUI cannot arm the queue or broaden
it to QEMU or malware. Keep `armed = false` in `plans/priority-queue.toml`
between campaigns. The current queue was deliberately armed on 2026-09-03 only
after all 2,046 cells passed resolution preflight and four SQLite/Readline
canaries passed end to end.

Operational notifications are always appended to the ignored local outbox
configured in the queue TOML. To add external delivery, set the named
`FIDB_NOTIFICATION_WEBHOOK_URL` to a reviewed HTTPS endpoint in the installed
0600 environment file; set `FIDB_NOTIFICATION_BEARER_TOKEN` only if that
endpoint requires it. Neither value is stored in TOML or the ledger.

When execution is deliberately approved, change `armed = false` to
`armed = true`, synchronize the queue again, and verify the resolved cells
before starting any worker.

After the queue is explicitly armed, start the complete qualified pool:

```sh
systemctl --user enable --now fidb-library-local-workers.target
systemctl --user status fidb-library-local-workers.target
journalctl --user -u 'fidb-library-local-worker@*.service' -f
```

The twenty-worker selection is grounded in the fixed-route OpenSSL measurement
at 94 GiB. It peaked at 50.52 GB aggregate worker RSS, leaving substantial
headroom on this host's current 93.93 GiB allocation. The resource gate still
checks available memory, disk, load and temperature before each new claim.
Twenty-nine workers remain an explicit burst experiment, not the default for
previously unmeasured libraries.

`[schedule].chain_batches = true` is enabled for the active short,
pre-materialized chunks and requires `finish_started_batch = true`. After one
chunk drains, a worker may admit the next only if the claim window is still
open. At 05:30 no new chunk starts, while the current chunk continues until it
drains. The generated queue remains disarmed; its reviewed active copy is
`plans/priority-queue.toml`.

Use the control panel's **Timing** workspace or inspect
`http://127.0.0.1:8765/api/v1/timings` on `reference-host`.  Require multiple
completed worker-monotonic samples for compile and Ghidra/FID stages, and review
their CPU and peak-RSS metrics, failures, retries, queue-wait basis and workflow
p50/p90 before raising the cap.  Coordinator-interrupted spans are diagnostic
evidence only and must not be treated as capacity samples.

Pause the coordinator before maintenance so no new jobs are claimed, wait for
active leases to drain, then stop the target and any individually enabled
instances.  A running worker reads the TOML once at process start, so editing
`armed = false` does **not** immediately gate that process.  Pause the live
ledger first; after changing TOML, run `fidb-poc queue sync` and confirm
`claimable = 0`.  Neither pause nor disarm terminates a cell that already holds
a lease.

The worker CLI exits with conventional status 130 or 143 when an operator stop
delivers SIGINT or SIGTERM. The unit declares those two planned-stop statuses
successful; other nonzero exits still leave the unit failed for inspection.

Enabled user units survive the controlling browser or SSH connection while
the KDE login remains active.  They do not survive the final logout or start
at boot until lingering is deliberately enabled for `fidb-operator`.  Enabling
linger is a host-level policy decision and also affects the user's other
enabled units; it is not performed merely by installing these templates.

## Authenticated remote workers

Remote machines must not mount or copy `var/fidb-coordinator/ledger.sqlite3`.
The reviewed `fidb-remote-worker-api.service` instead binds a worker-only API to
`127.0.0.1:8766`. It has no operator, plan-editing or raw-command endpoint. Do
not bind it to a wildcard or Tailscale address directly: publish only the
`/api/v1/worker/*` path through a reviewed, tailnet-restricted HTTPS reverse
proxy. The remote client rejects plain HTTP except loopback test mode.

Create a high-entropy token for each worker, give the plaintext only to that
worker, and put only its SHA-256 digest in a private coordinator file based on
`operations/remote-workers.json.example`:

```sh
install -m 0600 operations/remote-workers.json.example \
  "$HOME/.config/fidb-factory/remote-workers.json"
install -m 0644 operations/fidb-remote-worker-api.service \
  "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
```

Replace the example identity and all-zero digest before starting the service.
Every credential has an explicit pool allowlist. Credential changes require an
API restart; the file must remain mode 0600. After the HTTPS proxy is
independently reviewed, start and inspect the worker API:

```sh
systemctl --user enable --now fidb-remote-worker-api.service
systemctl --user status fidb-remote-worker-api.service
```

On a remote Linux worker with the same reviewed repository authorities and
tooling, install `remote-worker.env.example` as mode 0600, then review and
install `fidb-remote-library-worker.service`. The `library-local` pool covers
native Linux libraries, explicit-local source cross-builds, and archive
extraction.

The same authenticated transport now has a distinct `macos-native` pool. Add a
separate credential row using that pool, give the plaintext token only to the
Mac, and use a local Mac checkout at the exact coordinator revision. Install
`macos-worker.env.example` as
`~/.config/fidb-factory/macos-worker.env` with mode 0600, then run the read-only
host check:

```sh
./scripts/workers/macos-preflight.sh
```

This checks the command-free definition in `toolchains/external/`, Apple
hardware, ARM64 macOS, Xcode/SDK/Apple Clang, Java, Ghidra/PyGhidra, resources,
declared language smokes, and Mach-O/archive format. It does not contact the
coordinator, claim a lease, or build a library.

Only after a later run is explicitly reviewed and the queue is armed, use:

```sh
./scripts/workers/macos-run.sh --until-drained
```

The worker first registers its definition-bound preflight identity, checks its
own schedule and resource gates, re-resolves every leased cell locally, renews
the fence, streams timings, and uploads only the FIDB, FIDBF, and cell seal. The
coordinator repeats lease, identity, path, size, digest, seal, and timing checks
before atomic publication. Xcode, SDKs, credentials, build trees, and scratch
never return to Linux. See `docs/architecture/toolchains.md` and
`toolchains/external/README.md` for the complete boundary.
