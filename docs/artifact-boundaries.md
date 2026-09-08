# Artifact boundaries

The repository separates reviewed source authority from generated research
evidence and disposable execution state. A clean Git checkout contains the
software and the inputs needed to explain or reproduce work; it does not absorb
the outputs of a campaign merely because those outputs are valuable.

## Tracked source authority

These trees are reviewed and versioned:

- `src/`, `ghidra_scripts/` and `control-panel/` contain executable source;
- `recipes/`, `toolchains/`, `targets/`, `performance/`, `retention/`,
  `validation/` and the stable files under `plans/` contain TOML authority;
- `tests/` and small, deliberately selected fixtures establish behaviour;
- documentation records stable contracts and reviewed operational procedures.

Generated plans may be tracked only when a checked-in authority and a drift
test make their derivation explicit. A generated file is never edited by hand.

## Durable generated evidence

The following local trees are intentionally outside Git:

- `artifacts/runs/` and `artifacts/validation-runs/` hold sealed campaign output;
- `artifacts/fid-matching-runs/`, `artifacts/hash-discrimination/` and
  `artifacts/linked-reference-runs/` hold validation and comparison evidence;
- `qualification/evidence/` holds generated qualification observations;
- `artifacts/exports/` holds safeguards, expanded inspection copies and portable
  release archives;
- `artifacts/repository-safeguards/` holds local Git recovery bundles.

These paths may be large. Retention is controlled by their evidence manifests,
checksums, holds and the retention workflow—not by Git. A handoff that needs
research evidence must transfer the selected artifact package separately from
the source checkout.

## Reproducible local state

`var/`, `work/`, downloaded sources, prepared toolchains, virtual environments,
frontend build output and language caches are local execution state. They are
ignored and may be reconstructed from reviewed authority, subject to upstream
availability and pinned digests.

Do not delete local state merely to obtain a clean `git status`. Use the
retention collector for evidence-bearing data and verify the resulting manifest
before applying a deletion plan.

## Repository safeguard

Before Git maintenance, create and verify a bundle containing every reachable
ref. Record its SHA-256 digest outside the bundle. Temporary `tmp_pack_*` and
`tmp_obj_*` files may be removed only after:

1. no Git writer is active;
2. `git fsck --connectivity-only` succeeds;
3. the bundle verifies successfully; and
4. the exact temporary-file inventory and recoverable byte count are recorded.

Git maintenance never replaces the retention workflow and never removes
research artifacts.
