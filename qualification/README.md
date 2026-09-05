# Recipe qualification

Recipe qualification is the mandatory compilation-only gate between a
reviewed recipe and a campaign queue candidate. It tests the target-family and
oldest compiler-generation edges before a much larger width run can be
materialized.

The policy is defined by `pipeline.toml`. It requires a current digest-bound
seal, embeds that seal in generated plans, requires a later full-path canary,
and never arms a queue automatically. `c-cohort-template.toml` freezes the
current reusable 16-route/O2 edge set for future C cohorts; it is a template,
not an executable cohort authority.

Read status without compiling:

```sh
uv run fidb-poc qualification status --project-root .
```

Execute one explicitly selected qualification authority only after reviewing
its source, recipe and route set:

```sh
uv run fidb-poc qualify-recipes qualification/c11-c20.toml --project-root .
```

If an authority input changes, old evidence becomes stale and cannot unlock
materialization. Preserve it and explicitly restart into an archived evidence
generation:

```sh
uv run fidb-poc qualify-recipes qualification/c11-c20.toml \
  --project-root . --restart-stale
```

Successful evidence includes the authority/input digests and produces a
deterministic seal. Failed and interrupted attempts remain diagnostic evidence.
Never edit a report to make a gate pass and never infer qualification from a
batch's `materializable_executions` count.

After the seal is current, the supported promotion chain is:

1. regenerate the time model;
2. run `fidb-poc auto-batches` in preview mode;
3. write the short-chunk candidate queue with `--write`;
4. verify every generated plan and embedded qualification seal;
5. copy/review it as the active queue while paused and disarmed;
6. synchronize and run a full-path canary; and
7. arm only through the explicit operator boundary.

The generated queue is never active merely because qualification passed.
