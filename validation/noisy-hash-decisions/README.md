# Noisy-hash decisions

The control panel writes one small, reviewable TOML file per managed noisy
signature. A decision never deletes raw evidence or mutates a published lane
database. `quarantine` is a forward admission instruction: future compact lane
generations and matching-policy exports must omit that signature from automatic
ablation until it is reviewed. Existing generations remain immutable.

Allowed dispositions are `observe`, `quarantine`, `reviewed-shared`, and
`cleared`. Every change requires a reason and records the source ledger digest,
reviewer and UTC timestamp, making trust decisions auditable and reversible.
