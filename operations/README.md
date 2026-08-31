# Local library worker pool

These inactive user-service templates expose the loopback coordinator API and
run only the repository's native and explicit local cross-build library queue.
They are not for QEMU cells or malware work.  Nothing in this directory
installs, enables, arms, or starts an API or worker.

On `reference-host`, the first native commissioning run installed these templates
for `fidb-operator`, completed zlib and bzip2, then paused and disarmed the queue.
The commissioning record says the two worker instances were disabled after
the drain and the loopback API and production panel were left enabled for
inspection. Verify their current state with `systemctl --user status`: the
user does not have lingering enabled, so a final logout can stop them. This
dated record does not turn the repository files into an installer and does not
imply that later checkout changes reached the installed copies.

The host has 16 physical cores/32 hardware threads, but each reviewed build
adapter may use four make jobs and every worker embeds a Ghidra JVM.  The
current coordinator cap in `plans/priority-queue.toml` is two active leases.
The four units named by `fidb-library-local-workers.target` are a declared
expansion ceiling, not permission to run four jobs: with the current cap, any
additional service instances remain idle.  Do not interpret 32 hardware
threads as 32 safe end-to-end workers.

## Before activation

The queue must remain library-only: resolved cells must have `kind = "native"`,
`kind = "source-library"` with `executor = "local"`, or
`kind = "archive-library"` with `executor = "archive-local"`. Do not add a
malware batch or a QEMU route to the queue
used by these units.  The worker unit also passes `--pool library-local`, so it
must fail closed if a future queue attempts to offer either kind of work.
Inspect the complete resolution while it is still disarmed:

```sh
cd /home/fidb-operator/Projects/circl/FIDB-POC-unified
.venv/bin/fidb-poc queue sync --queue plans/priority-queue.toml --state var/fidb-coordinator/ledger.sqlite3 --full
.venv/bin/fidb-poc queue status --state var/fidb-coordinator/ledger.sqlite3 --full
```

Confirm that `/opt/ghidra/support/analyzeHeadless`, Java 21, the native route
tools, required pinned source/toolchain archives or network access, and ample
disk space are available.  The example environment limits each JVM to a 4 GiB
heap and four visible processors.  The service adds a 6 GiB soft memory limit,
an 8 GiB hard limit, and a four-CPU quota.

The units deliberately do not name `network.target` or
`network-online.target`: those are system-manager targets and do not exist in
the `fidb-operator` user manager.  Before starting workers that may acquire an
input, check connectivity explicitly (for example with
`/usr/bin/nm-online -q --timeout=60`).  This first native-only commissioning
run uses already reviewed public source URLs. Managed acquisition has bounded
timeouts, checksum verification, retry and a content-addressed cache. The queue
worker also enforces the TOML schedule, hard cutoff, durable retry backoff and
claim-time memory/disk/load/temperature gates.

Inspect that decision without mutating the ledger:

```sh
.venv/bin/fidb-poc queue preflight --queue plans/priority-queue.toml
```

The command returns nonzero while the queue is disarmed, outside its claim
window, or blocked by a resource threshold. The control panel reads the same
evaluation from the loopback API rather than inventing a second policy.

## Deliberately manual installation

Run these commands only after reviewing the paths and unit contents.  They are
instructions, not an installation script:

```sh
install -d -m 0755 "$HOME/.config/systemd/user" "$HOME/.config/fidb-factory"
install -m 0644 operations/fidb-coordinator-api.service "$HOME/.config/systemd/user/"
install -m 0644 operations/fidb-control-panel.service "$HOME/.config/systemd/user/"
install -m 0644 operations/fidb-library-local-worker@.service "$HOME/.config/systemd/user/"
install -m 0644 operations/fidb-library-local-workers.target "$HOME/.config/systemd/user/"
install -m 0600 operations/library-local-worker.env.example "$HOME/.config/fidb-factory/library-local-worker.env"
systemctl --user daemon-reload
```

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

The reviewed unit binds only the current `reference-host` Tailscale address,
`127.0.0.1`, on port 3001 and injects the loopback API origin server-side.
If the Tailscale address changes, update and reinstall the reviewed unit rather
than broadening it to an all-interface listener.

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
it to QEMU or malware. Leave `armed = false` in
`plans/priority-queue.toml` until the resolved library-only queue and worker
prerequisites have been reviewed.

Operational notifications are always appended to the ignored local outbox
configured in the queue TOML. To add external delivery, set the named
`FIDB_NOTIFICATION_WEBHOOK_URL` to a reviewed HTTPS endpoint in the installed
0600 environment file; set `FIDB_NOTIFICATION_BEARER_TOKEN` only if that
endpoint requires it. Neither value is stored in TOML or the ledger.

When execution is deliberately approved, change `armed = false` to
`armed = true`, synchronize the queue again, and verify the resolved cells
before starting any worker.

Start and observe two workers first:

```sh
systemctl --user enable --now fidb-library-local-worker@1.service fidb-library-local-worker@2.service
systemctl --user status fidb-library-local-worker@1.service fidb-library-local-worker@2.service
journalctl --user -u 'fidb-library-local-worker@*.service' -f
```

For the two-cell commissioning queue, the foreground zlib canary consumes the
first cell.  Expect worker 1 or worker 2 to claim the remaining bzip2 cell and
the other instance to remain idle; do not replay zlib merely to make both
workers busy.  Enable the two instances explicitly.  Do not enable the
four-instance target during this smoke.

Only after representative library cells complete without sustained memory,
swap, or storage pressure should a four-worker configuration be reviewed.  A
reviewed expansion requires changing `max_workers` from 2 to 4 in the TOML,
synchronizing and inspecting the queue again, and then explicitly enabling the
four-instance target:

Use the control panel's **Timing** workspace or inspect
`http://127.0.0.1:8765/api/v1/timings` on `reference-host`.  Require multiple
completed worker-monotonic samples for compile and Ghidra/FID stages, and review
their CPU and peak-RSS metrics, failures, retries, queue-wait basis and workflow
p50/p90 before raising the cap.  Coordinator-interrupted spans are diagnostic
evidence only and must not be treated as capacity samples.

```sh
systemctl --user enable --now fidb-library-local-workers.target
```

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
install `fidb-remote-library-worker.service`. The environment supplies the HTTPS
origin, worker identity and plaintext token. The client checks its own schedule
and resource gates, re-resolves every leased cell locally, renews the fence,
streams timing, and uploads only the three material sealed outputs. The
coordinator repeats identity, timing, path, size and digest checks before it can
mark the job complete.

The current authorized pool is still `library-local`: native Linux libraries,
explicit-local source cross-builds and archive extraction. This transport is
ready for remote Linux workers, but it does not invent macOS/Windows recipes or
make the present Linux-only cells portable to those hosts.
