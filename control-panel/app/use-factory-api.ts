'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

export type ConnectionState = 'connecting' | 'live' | 'stale' | 'offline';

export type CoordinatorCounts = Record<
  'blocked' | 'complete' | 'failed' | 'leased' | 'queued' | 'running',
  number
>;

export type CoordinatorBatch = {
  id: string;
  name: string;
  position: number;
  plan_path: string;
  plan_digest: string;
  matrices: string[] | null;
  active: boolean;
};

export type CoordinatorJob = {
  job_id: string;
  batch_id: string;
  batch_position: number;
  base_cell: string;
  position: number;
  state: keyof CoordinatorCounts;
  current_stage: string | null;
  leased_by: string | null;
  attempt_count: number;
  eligible_at?: number;
  blockers: string[];
  result: Record<string, unknown> | null;
  error: string | null;
};

export type CoordinatorAttempt = {
  attempt_id: number;
  job_id: string;
  attempt_number: number;
  lease_generation: number;
  worker_id: string;
  state: 'leased' | 'running' | 'complete' | 'failed' | 'expired';
  started_at: string;
  lease_expires_at: number;
  ended_at: string | null;
  duration_ns: number | null;
  duration_source: 'coordinator-wall-clock' | null;
  error: string | null;
  queue_wait_duration_ns?: number | null;
  queue_wait_source?: 'coordinator-wall-clock' | null;
  queue_wait_basis?: string | null;
};

export type StageSpanState =
  | 'started'
  | 'completed'
  | 'failed'
  | 'skipped'
  | 'interrupted';

export type StageSpan = {
  stage_attempt_id: number;
  attempt_id: number;
  job_id: string;
  attempt_number: number;
  lease_generation: number;
  worker_id: string;
  sequence: number;
  stage: string;
  stage_attempt: number;
  state: StageSpanState;
  started_at: string;
  ended_at: string | null;
  duration_ns: number | null;
  duration_source: 'worker-monotonic' | 'coordinator-wall-clock' | null;
  wall_clock_regressed: boolean;
  details: Record<string, unknown> | null;
  metrics: Record<string, unknown> | null;
  error: string | null;
};

export type CoordinatorWorker = {
  worker_id: string;
  transport: 'local' | 'remote-http';
  pools: string[];
  state: 'online' | 'offline';
  metadata: Record<string, unknown>;
  registered_at: string;
  last_seen_at: string;
};

export type CoordinatorSnapshot = {
  schema_version: string;
  status: 'disarmed' | 'paused' | 'ready' | 'active' | 'idle';
  config_name: string | null;
  armed: boolean;
  paused: boolean;
  max_workers: number;
  performance_profile?: PerformanceProfile | null;
  active_workers: number;
  available_worker_slots: number;
  poll_seconds: number;
  lease_seconds: number;
  max_attempts: number;
  retry_backoff_seconds?: number;
  retry_backoff_max_seconds?: number;
  sync_generation: number;
  synced_at: string | null;
  counts: CoordinatorCounts;
  claimable: number;
  retry_wait?: number;
  operations?: Record<string, unknown>;
  execution_block?: {
    active: boolean;
    batch_id: string | null;
    admission_id: string | null;
    last_schedule_admission_id: string | null;
    counts?: CoordinatorCounts;
    remaining?: number;
  };
  last_event_id: number;
  batches: CoordinatorBatch[];
  jobs: CoordinatorJob[];
  attempts?: CoordinatorAttempt[];
  workers?: CoordinatorWorker[];
  stage_attempts?: StageSpan[];
  attempts_total?: number;
  attempts_truncated?: boolean;
  stage_attempts_total?: number;
  stage_attempts_truncated?: boolean;
  snapshot_detail?: 'full' | 'control-panel';
};

export type OperationsPreflight = {
  schema_version: string;
  checked_at: string;
  ready: boolean;
  queue_armed: boolean;
  schedule: {
    claims_allowed: boolean;
    reason: string;
    window_started_at: string | null;
    stop_claiming_at: string | null;
    hard_cutoff_at: string | null;
    next_window_at: string | null;
  };
  resources: {
    passed: boolean;
    reasons: string[];
    metrics: {
      available_memory_gib: number;
      free_disk_gib: number;
      load_1m: number;
      logical_cpus: number;
      load_per_cpu: number;
      temperature_c: number | null;
    };
  };
  policy: {
    schedule: Record<string, unknown>;
    resources: Record<string, number>;
    notifications: Record<string, unknown>;
  };
};

export type TimingDistribution = {
  min: number;
  p50: number;
  p90: number;
  p95: number;
  max: number;
  mean: number;
};

export type StageTimingAggregate = {
  stage: string;
  sample_count: number;
  state_counts: Record<string, number>;
  duration_ns: TimingDistribution | null;
  duration_source?: 'worker-monotonic';
};

export type WorkflowTimingAggregate = {
  workflow: string;
  sample_count: number;
  state_counts: Record<string, number>;
  duration_ns: TimingDistribution | null;
  duration_source?: 'coordinator-wall-clock';
  queue_wait_duration_ns: TimingDistribution | null;
  queue_wait_source?: 'coordinator-wall-clock';
  queue_wait_basis?: string | null;
};

export type TimingEta = Record<string, unknown> & {
  sample_count?: number;
  confidence?: string;
  projected_completion_at?: string;
  remaining_duration_ns?: number;
  p50_remaining_duration_ns?: number;
  p90_remaining_duration_ns?: number;
};

export type TimingSnapshot = {
  schema_version: 'fidb-timings/v1' | string;
  generated_at: string;
  limit: number;
  aggregate_sample_limit: number;
  aggregates_truncated: boolean;
  sample_policy?: {
    stage_percentiles: string;
    workflow_percentiles: string;
    interrupted_spans: string;
    aggregate_selection: string;
    queue_wait_basis: string;
    service_rate: string;
  };
  sample_counts: {
    stage_spans: number;
    completed_stage_spans: number;
    completed_workflows: number;
  };
  throughput: {
    kind: 'successful-attempt-service-rate-proxy' | string;
    sample_count: number;
    basis: 'completed-successful-final-attempt-wall-clock' | string;
    scope: 'excludes-retries-queue-idle-and-worker-concurrency' | string;
    service_jobs_per_hour: number;
  } | null;
  eta: TimingEta | null;
  stages: StageTimingAggregate[];
  workflows: WorkflowTimingAggregate[];
  recent: StageSpan[];
};

export type CapabilityReadiness = {
  job_id: string;
  batch_id: string;
  job_state: string;
  kind: string;
  executor: string;
  library_local_eligible: boolean;
  readiness: string;
  reasons: string[];
};

export type ToolchainCapability = {
  id: string;
  family: string;
  version: string;
  variant: string;
  capabilities: string[];
  state: string;
  target: {
    machine: string;
    endianness: string;
    elf_class: number;
    cross_arch: string | null;
  };
  archives: Record<string, {
    expected_sha256: string;
    observed_sha256?: string;
    path: string;
    bytes: number | null;
    state: string;
  }>;
  cross_bin_prefix?: string | null;
  prepared_state?: string;
};

export type ToolchainPack = {
  id: string;
  label: string;
  kind: 'compiler-sysroot' | 'compiler-tooling' | 'toolchain-builder-source';
  target_ids: string[];
  compiler_family: string;
  compiler_version: string;
  compiler_driver: string;
  linker_family: string;
  linker_version: string;
  runtime: string;
  runtime_version: string;
  url: string;
  sha256: string;
  download_bytes: number;
  installed_bytes_estimate: number;
  size_evidence: string;
  license_ids: string[];
  upstream_release: string;
  upstream_authority: string;
  archive_root: string;
};

export type ToolchainPackInput = {
  id: string;
  label: string;
  kind: 'user-supplied-sdk';
  target_ids: string[];
  source_policy: string;
  required_metadata: string[];
  state: string;
  authority: string;
};

export type ToolchainQualification = {
  id: string;
  route_id: string;
  tool_source: 'pack' | 'composed-route';
  tool_pack_id: string;
  driver_pattern: string;
  cxx_driver_pattern: string;
  archiver_pattern: string;
  version_contains: string;
  smoke_languages: Array<'c' | 'cpp'>;
  composition: 'none' | 'osxcross-llvm';
};

export type ToolchainRouteQualification = {
  definition: ToolchainQualification;
  state: 'blocked-by-prerequisites' | 'composition-required' | 'missing' | 'qualified' | 'broken' | 'broken-composition';
  route_material_digest: string | null;
  path: string | null;
  record: Record<string, unknown> | null;
  composition?: {
    state: 'missing' | 'composed' | 'broken';
    path: string;
    root: string;
    manifest: Record<string, unknown> | null;
    host_dependencies: Array<{ name: string; path: string | null; available: boolean }>;
  };
};

export type ToolchainPackRoute = {
  id: string;
  label: string;
  target_id: string;
  compiler_id: string;
  coverage_requirement_id: string;
  compiler_family: string;
  target_triple: string;
  evidence_role: 'primary' | 'cross-build' | 'native-reference';
  provisioning: 'downloadable-pack' | 'pack-plus-user-input' | 'external-worker';
  pack_ids: string[];
  input_ids: string[];
  worker_class: string;
  qualification_state: string;
  additional_installed_bytes_estimate: number;
  additional_size_evidence: string;
  external_requirements: string[];
};

export type ToolchainPackProfile = {
  schema_version: 'fidb-toolchain-profile/v1';
  id: string;
  label: string;
  language_id: string;
  host_system: string;
  host_architecture: string;
  route_ids: string[];
  external_policy: 'report';
  purpose: string;
  authority: string;
  authority_path: string;
};

export type ToolchainProfilePlan = {
  schema_version: 'fidb-toolchain-profile-plan/v3';
  operation: 'plan' | 'status' | 'pull' | 'prepare' | 'compose' | 'qualify';
  profile: ToolchainPackProfile;
  catalog_digest: string;
  profile_digest: string;
  state: 'blocked' | 'acquisition-required' | 'preparation-required' | 'input-required' | 'input-and-external-required' | 'composition-required' | 'qualification-required' | 'qualified-external-required' | 'qualified';
  host: {
    required_system: string;
    required_architecture: string;
    detected_system: string;
    detected_architecture: string;
    compatible: boolean;
  };
  managed_downloads: string;
  managed_prepared: string;
  managed_inputs: string;
  managed_bindings: string;
  managed_composed: string;
  managed_qualified: string;
  summary: {
    routes: number;
    coverage_requirements: number;
    downloadable_routes: number;
    user_input_routes: number;
    external_routes: number;
    primary_routes: number;
    cross_build_routes: number;
    native_reference_routes: number;
    packs: number;
    verified_cached_packs: number;
    missing_packs: number;
    broken_packs: number;
    prepared_packs: number;
    missing_preparations: number;
    broken_preparations: number;
    inputs: number;
    bound_inputs: number;
    missing_inputs: number;
    broken_inputs: number;
    composed_routes: number;
    missing_compositions: number;
    qualified_routes: number;
    missing_qualifications: number;
    broken_routes: number;
    download_bytes: number;
    cached_download_bytes: number;
    remaining_download_bytes: number;
    pack_installed_bytes_estimate: number;
    route_additional_installed_bytes_estimate: number;
    installed_bytes_estimate: number;
    installed_size_evidence: string;
  };
  routes: Array<ToolchainPackRoute & {
    state: string;
    qualification?: ToolchainRouteQualification;
  }>;
  packs: Array<ToolchainPack & {
    state: 'missing' | 'verified-cached' | 'broken';
    cache: { path: string; bytes: number | null; observed_sha256: string | null };
    preparation: {
      state: 'missing' | 'prepared' | 'broken';
      path: string;
      root: string;
      manifest: Record<string, unknown> | null;
    };
  }>;
  inputs: Array<ToolchainPackInput & {
    binding: {
      state: 'missing' | 'bound-verified' | 'broken';
      path: string;
      material_path: string | null;
      document: Record<string, unknown> | null;
    };
  }>;
  requirements: Array<{
    code: string;
    severity: 'action' | 'constraint' | 'blocker';
    route_id?: string;
    pack_id?: string;
    input_id?: string;
    message: string;
    details?: string[] | { source_policy: string; required_metadata: string[] };
  }>;
  recommended_next_action: string;
  cli_examples: Array<{ action: 'plan' | 'status' | 'pull' | 'prepare' | 'compose' | 'qualify'; argv: string[]; shell: string }>;
  trace: {
    sources: Record<string, string>;
    source_digests: Record<string, string>;
    profile_authority: string;
  };
};

export type ToolchainPackCatalog = {
  schema_version: 'fidb-toolchain-pack-catalog/v4';
  host: { system: string; architecture: string };
  source_authority: string;
  cache_policy: string;
  packs: ToolchainPack[];
  compilers: Array<{
    id: string;
    family: string;
    version: string;
    generation: string;
    language_ids: string[];
    release_authority: string;
  }>;
  compiler_width: {
    schema_version: string;
    purpose: string;
    selection: {
      gcc_compiler_ids: string[];
      llvm_mingw_compiler_ids: string[];
      deferred_families: string[];
      selection_reason: string;
    };
  };
  inputs: ToolchainPackInput[];
  routes: ToolchainPackRoute[];
  qualifications: ToolchainQualification[];
  profiles: ToolchainPackProfile[];
  sources: Record<string, string>;
  source_digests: Record<string, string>;
  catalog_digest: string;
};

export type FactoryCapabilities = {
  schema_version: string;
  detection_mode: 'read-only';
  host: {
    system: string;
    machine: string;
    physical_cores: number;
    logical_cpus: number | null;
    smt_siblings: number;
    threads_per_core: number;
    memory_bytes: number | null;
    available_memory_bytes: number;
    memory_model: 'dedicated-system-memory' | 'unified';
    capacity: {
      schema_version: 'fidb-host-capacity/v1';
      system: string;
      architecture: string;
      physical_cores: number;
      logical_cpus: number;
      smt_siblings: number;
      threads_per_core: number;
      total_memory_mib: number;
      available_memory_mib: number;
      memory_model: 'dedicated-system-memory' | 'unified';
      cpu_affinity_limited: boolean;
      cgroup_cpu_quota: number | null;
      cgroup_memory_limit_mib: number | null;
      sources: Record<string, string>;
    };
  };
  automatic_performance: {
    selector_version: string;
    effective_settings: {
      worker_mode: 'fixed';
      workers: number;
      build_jobs_per_cell: number;
      ghidra_heap_mib: number;
      ghidra_core_limit: number;
    };
    bounds: {
      cpu_workers: number;
      memory_workers: number;
      memory_reserve_mib: number;
      per_worker_budget_mib: number;
      maximum_workers: number;
    };
    policy: {
      physical_core_weight: number;
      smt_sibling_weight: number;
      memory_basis: string;
      live_pressure: string;
    };
  };
  analysis: {
    ready: boolean;
    ghidra: { state: string; path: string | null; version?: string | null };
    java: { available: boolean; path: string | null; version: string | null };
    pyghidra: { available: boolean; version: string | null };
  };
  worker_pools: {
    'library-local': WorkerPoolCapabilities;
    'macos-native'?: WorkerPoolCapabilities & {
      external_registration_required?: boolean;
    };
  };
  active_job_readiness: CapabilityReadiness[];
  native_routes: Array<{
    id: string;
    target: { os: string; architecture: string; binary_format: string };
    tools: Record<string, { configured: string[]; available: boolean; path: string | null }>;
    ready: boolean;
  }>;
  toolchains: {
    registry_path: string;
    managed_cache: string;
    managed_preparation: boolean | 'per-attempt-extraction';
    entries: ToolchainCapability[];
  };
  toolchain_profiles: {
    managed_downloads: string;
    plans: ToolchainProfilePlan[];
  };
};

export type LaneWidthRun = {
  width_id: string;
  run_id: string;
  path: string;
  state: string;
  mode: string | null;
  fixed_recipe: string | null;
  started_at_utc: string | null;
  finished_at_utc: string | null;
  wall_time_ns: number;
  parallel_workers: number;
  scheduled_executions: number;
  completed_executions: number;
  failed_executions: number;
  successful_route_profile_pairs: number;
  signature_records: number;
  unique_signatures: number;
  retained_bytes: number;
  peak_scratch_bytes: number;
  result_bytes: number;
  modified_at_utc: string;
};

export type PerformanceProfile = {
  id: string;
  label: string;
  description: string;
  qualification: 'current-default' | 'portable-starting-point' | 'measured-openssl' | 'derived-from-measured-openssl';
  guidance: string;
  evidence_path: string | null;
  host: {
    system: string;
    architecture: string;
    physical_cores: number | null;
    logical_cpus: number | null;
    memory_mib: number | null;
    memory_model: 'dedicated-system-memory' | 'unified';
  };
  settings: {
    worker_mode: 'automatic' | 'fixed';
    workers: number | null;
    build_jobs_per_cell: number;
    ghidra_heap_mib: number | null;
    ghidra_core_limit: number | null;
  };
  resolution?: FactoryCapabilities['automatic_performance'] | null;
};

export type PerformanceProfiles = {
  schema_version: 'fidb-performance-profiles/v2';
  default_profile: string;
  authority_path: string;
  automatic_policy: FactoryCapabilities['automatic_performance']['policy'];
  profiles: PerformanceProfile[];
};

export type LaneDatabaseGeneration = {
  kind: 'raw' | 'compact';
  path: string;
  bytes: number;
  modified_at_utc: string;
  generation_id: string;
  source_generation_id: string | null;
  source_run_id: string | null;
  lane_id: string;
  sublane_ids: string[];
  state: string;
  created_at: string;
  evidence_kind: string;
  raw_observations: number;
  unique_signatures: number | null;
  repeated_observations: number | null;
  repetition_fraction: number | null;
  relationships: number;
  native_projections: number;
  native_projection_state: string;
  ecological_validation_state: string;
  admission_states?: Record<string, number>;
  active: boolean;
};

export type LaneInventory = {
  schema_version: 'fidb-lane-inventory/v1';
  detection_mode: 'read-only-metadata';
  roots: { width_runs: string; lane_databases: string };
  inspection: {
    sqlite_open_mode: string;
    content_digests: string;
    full_integrity_check: string;
  };
  summary: {
    width_runs: number;
    complete_width_runs: number;
    raw_generations: number;
    compact_generations: number;
    materialized_generations: number;
    active_packs: number;
    lane_database_bytes: number;
    raw_observations: number;
    compact_unique_signatures: number;
    issues: number;
  };
  latest_complete_width_run: LaneWidthRun | null;
  width_runs: LaneWidthRun[];
  databases: LaneDatabaseGeneration[];
  issues: Array<{ path: string; reason: string }>;
};

type WorkerPoolCapabilities = {
      cell_kinds: string[];
      source_executor: 'local' | 'native-local';
      qemu_required: false;
      eligible_jobs: number;
      ready_now: number;
      runnable_with_pinned_acquisition: number;
      blocked: number;
      max_workers?: number;
      active_workers?: number;
      available_worker_slots?: number;
      excluded_cell_kinds?: string[];
};

export type CoordinatorEvent = {
  event_id: number;
  occurred_at: string;
  event_type: string;
  actor: string;
  batch_id: string | null;
  job_id: string | null;
  plan_digest: string | null;
  payload: Record<string, unknown>;
};

export type AuthorityRecipe = {
  id: string;
  kind: 'native' | 'source-library' | 'malware';
  mode: 'native' | 'source';
  name: string;
  version: string;
  url: string;
  sha256: string;
  build_adapter: string;
  authority_path: string;
  static_archives?: string[];
  library_path?: string;
  toolchain_family?: string;
  toolchain_variants?: string[];
};

export type AuthorityToolchain = {
  id: string;
  family: string;
  version: string;
  variant: string;
  machine: string;
  endianness: string;
  elf_class: number;
  archive_capable: boolean;
  source_capable: boolean;
  cross_arch: string | null;
  cross_bin_prefix: string | null;
};

export type AuthorityTarget = {
  id: string;
  label: string;
  platform: string;
  architecture: string;
  machine: string;
  binary_format: string;
  endianness: string;
  bits: number;
  catalog_state: 'reviewed-route' | 'reviewed-abi' | 'study-observed' | string;
  evidence: string[];
  native_route_ids: string[];
  toolchain_ids: string[];
  source_capable_toolchain_ids: string[];
  archive_capable_toolchain_ids: string[];
  managed_route_ids: string[];
  managed_pack_ids: string[];
};

export type AuthorityLaneSublane = {
  id: string;
  target_id: string;
  policy_id: string;
  definition_state: 'mapped' | 'unresolved';
  ghidra_language_ids: string[];
  compiler_spec_ids: string[];
  target: Omit<AuthorityTarget, 'native_route_ids' | 'toolchain_ids' | 'source_capable_toolchain_ids' | 'archive_capable_toolchain_ids' | 'managed_route_ids' | 'managed_pack_ids'>;
};

export type AuthorityLane = {
  id: string;
  label: string;
  platform: string;
  architecture_family: string;
  state: 'experimental' | 'active' | 'retired';
  description: string;
  sublanes: AuthorityLaneSublane[];
};

export type AuthorityLaneRegistry = {
  schema_version: 'fidb-lanes/v1';
  authority_path: string;
  policies: Array<{
    id: string;
    ghidra_version: string;
    ghidra_release: string;
    ghidra_build: string;
    analysis_profile: string;
    fid_algorithm: string;
  }>;
  lanes: AuthorityLane[];
};

export type AuthorityFactor = {
  id: string;
  stage: string;
  label: string;
  control: string;
  evidence: string;
  confidence: string;
  impact: string;
  coverage_action: string;
};

export type AuthorityFactorVariant = {
  id: string;
  factor: string;
  group: string;
  label: string;
  state: string;
  authority: string;
};

export type AuthorityPlan = {
  path: string;
  toml_sha256: string;
  name: string;
  policy: { max_cells: number; priority: string };
  coverage: { factor_variants: string[] };
  queue: { strategy: string; recipe_order: string[] };
  matrices: Array<Record<string, unknown>>;
  plan_digest: string;
  summary: Record<string, number>;
  inventory: {
    summary: Record<string, number>;
    cells: Record<string, { state: string; evidence: string[]; note: string }>;
  };
};

export type CoverageDimension = {
  id: string;
  label: string;
  layer: string;
  description: string;
  matrix_role: 'multiplier' | 'applicability' | 'bounded-profile' | 'analysis-reuse' | 'policy-control';
  facets: string[];
  factor_ids?: string[];
};

export type CoverageCompilerFamily = {
  id: string;
  label: string;
  route_scope: string;
  state: 'catalogued' | 'desired' | 'guarded' | 'study-observed';
  language_ids: string[];
  version_strategy: string;
  settings: string[];
};

export type CoverageLanguage = {
  id: string;
  label: string;
  state: 'active-scope' | 'designed' | 'vocabulary-only';
  scope: string;
  denominator: string;
  treatment_axes: string[];
  toolchain_family_ids: string[];
  caveat: string;
  authority: string;
};

export type CoverageProfile = {
  id: string;
  label: string;
  compiler_family: string;
  optimization: string;
  controls: string[];
  route_scope: string;
  state: 'catalogued' | 'desired' | 'guarded' | 'study-observed';
  language_id: string;
  evidence_class: 'measured' | 'proposed' | 'provisional' | 'assumption';
};

export type CoverageScenario = {
  id: string;
  label: string;
  library_families: number;
  releases: number;
  routes: number;
  profiles: number;
  unique_executions: number;
  replay_multiplier: number;
  replayed_executions: number;
  scope: string;
  caveat: string;
  language_id: string;
  evidence_class: 'measured' | 'proposed' | 'provisional' | 'assumption';
  authority: string;
};

export type CoverageUniverse = {
  schema_version: 'fidb-coverage-universe/v2';
  authority_path: string;
  population: {
    published_four_source_n80_families: number;
    tier_zero_families: number;
    published_priority_head_families: number;
    nine_source_candidate_spine_keys: number;
    nine_source_shared_frontier_keys: number;
    nine_source_n80_candidate_rank: number;
    global_family_lower_estimate: number;
    global_family_central_estimate: number;
    global_family_upper_estimate: number;
    population_caveat: string;
  };
  dimensions: CoverageDimension[];
  languages: CoverageLanguage[];
  compiler_families: CoverageCompilerFamily[];
  profiles: CoverageProfile[];
  scenarios: CoverageScenario[];
};

export type WidthAxisId =
  | 'releases'
  | 'routes'
  | 'build_profiles'
  | 'artifact_shapes'
  | 'analysis_profiles'
  | 'admission_profiles'
  | 'replay';

export type WidthStudyAxis = {
  id: WidthAxisId;
  label: string;
  layer: 'build-cell' | 'analysis-reuse' | 'policy-reuse' | 'repeat';
  minimum: number;
  default: number;
  maximum: number;
  unit: string;
  description: string;
};

export type WidthStudyMetrics = {
  build_width_per_family: number;
  build_cells: number;
  analysis_runs: number;
  replayed_executions: number;
  policy_evaluations: number;
};

export type WidthStudyPreset = Record<WidthAxisId, number> & {
  id: string;
  label: string;
  evidence_class: 'measured' | 'proposed' | 'provisional' | 'assumption';
  description: string;
  metrics: WidthStudyMetrics;
};

export type WidthStudyFamily = {
  rank: number;
  id: string;
  label: string;
  source_url: string;
  source_state: string;
  selection_evidence: string;
  recipe_ids: string[];
  recipe_state: 'reviewed-recipe' | 'source-evidence' | 'recipe-required';
};

export type WidthStudyToolchainRequirement = {
  order: number;
  id: string;
  target_id: string;
  target_label: string;
  target_catalog_state: string;
  compiler_family: string;
  compiler_label: string;
  wave: string;
  worker_class: string;
  acquisition: string;
  version_policy: string;
  rationale: string;
  route_state: 'installed' | 'pinned-source' | 'archive-only' | 'remote-required' | 'definition-required';
  native_route_ids: string[];
  source_capable_toolchain_ids: string[];
  archive_capable_toolchain_ids: string[];
};

export type WidthStudy = {
  schema_version: 'fidb-width-study/v1';
  id: string;
  name: string;
  label: string;
  language_id: string;
  state: 'defined-disarmed' | string;
  selection_status: string;
  family_count: number;
  default_preset: string;
  purpose: string;
  ranking_authority: string;
  ranking_snapshot: string;
  queue_policy: string;
  caveat: string;
  authority_path: string;
  scaling: {
    comparison_family_counts: number[];
    default_target_families: number;
    default_workers: number;
    maximum_workers: number;
    model: string;
  };
  calibration: {
    evidence_class: 'measured';
    sample_count: number;
    successful_wall_ns_min: number;
    successful_wall_ns_p50: number;
    successful_wall_ns_max: number;
    retained_bundle_bytes_p50: number;
    compact_output_bytes_p50: number;
    peak_worker_rss_bytes_p50: number;
    scratch_peak_state: string;
    basis: string;
    caveat: string;
  };
  toolchain_requirements: WidthStudyToolchainRequirement[];
  families: WidthStudyFamily[];
  axes: WidthStudyAxis[];
  presets: WidthStudyPreset[];
  readiness: {
    reviewed_recipe_families: number;
    reviewed_recipe_releases: number;
    source_evidence_families: number;
    missing_recipe_families: number;
    catalogued_target_contexts: number;
    registered_route_contexts: number;
    default_route_state_counts: Record<WidthStudyToolchainRequirement['route_state'], number>;
    executable_treatments: number;
    queue_state: 'not-materialized' | string;
    blockers: string[];
  };
};

export type WidthCompilation = {
  schema_version: 'fidb-width-compilation/v1';
  compilation_digest: string;
  id: string;
  label: string;
  state: string;
  language_id: string;
  purpose: string;
  fixed_recipe: string;
  toolchain_profile: string;
  route_profile_digest: string;
  freeze?: {
    evidence_path: string;
    evidence_sha256: string;
    executed_compilation_digest: string;
    completed_executions: number;
    wall_time_ns: number;
    peak_active_replay_scratch_bytes: number;
    final_scratch_bytes: number;
    retained_bytes: number;
    artifact_byte_identical_cells: number;
    fid_semantic_identical_cells: number;
  } | null;
  routes: Array<{
    id: string;
    label: string;
    target_id: string;
    target_os: string;
    architecture: string;
    binary_format: string;
    compiler_family: string;
    compiler_id: string;
    toolchain_state: string;
    toolchain_identity: string;
  }>;
  build_profiles: Array<{
    id: string;
    label: string;
    compiler_family: string;
    optimization: string;
    controls: string[];
    state: string;
    execution_treatment?: string;
  }>;
  artifact_profiles: Array<{ id: string; label: string; state: string; description: string }>;
  analysis_profiles: Array<{ id: string; label: string; state: string; variant_id: string; description: string }>;
  admission_profiles: Array<{ id: string; label: string; state: string; description: string }>;
  factors: Array<AuthorityFactor & {
    variants: AuthorityFactorVariant[];
    variant_state_counts: Record<string, number>;
  }>;
  applicability: Array<{
    route_id: string;
    profile_id: string;
    treatment_id?: string;
    state: 'executable' | 'inapplicable' | 'unimplemented' | 'unavailable';
    reasons: string[];
  }>;
  summary: {
    declared_route_slots: number;
    implemented_routes: number;
    qualified_routes: number;
    declared_build_profile_slots: number;
    catalogued_build_profiles: number;
    applicable_route_profile_pairs: number;
    executable_route_profile_pairs: number;
    unimplemented_applicable_pairs: number;
    inapplicable_pairs: number;
    feasible_build_cells: number;
    feasible_analysis_runs: number;
    feasible_policy_evaluations: number;
    selected_replay: number;
    feasible_full_path_executions: number;
    declared_maximum_build_cells_one_family: number;
    declared_maximum_analysis_runs_one_family: number;
    declared_maximum_policy_evaluations_one_family: number;
    sensitivity_factors: number;
    factors_with_variants: number;
  };
};

export type WidthBatch = {
  schema_version: 'fidb-width-batch-compilation/v1';
  batch_digest: string;
  id: string;
  name: string;
  label: string;
  state: 'defined-disarmed';
  language_id: string;
  purpose: string;
  recipe_policy: string;
  queue_policy: string;
  authority_path: string;
  authority_sha256: string;
  authorities: {
    source_pack: string;
    source_pack_sha256: string;
    width: string;
    width_sha256: string;
    width_route_profile_digest: string;
    study: string;
    study_sha256: string;
  };
  libraries: Array<{
    rank: number;
    id: string;
    label: string;
    version: string;
    url: string;
    sha256: string;
    recipe_id: string;
    recipe_state: 'recipe-ready' | 'recipe-required' | 'recipe-source-mismatch';
    blocker: string;
  }>;
  summary: {
    libraries: number;
    route_profiles: number;
    compiler_identities: number;
    executable_treatments: number;
    executions_per_library: number;
    total_executions: number;
    applicable_pairs_per_library: number;
    unimplemented_pairs_per_library: number;
    declared_maximum_build_cells: number;
    locally_qualified_routes: number;
    locally_executable_per_library: number;
  };
  readiness: {
    source_pins: number;
    recipe_ready_libraries: number;
    recipe_blocked_libraries: number;
    toolchain_ready_routes: number;
    toolchain_blocked_routes: number;
    materializable_executions: number;
    blocked_executions: number;
    queue_state: 'not-materialized-disarmed';
    blockers: string[];
  };
};

export type FactoryAuthority = {
  schema_version: 'fidb-authority-catalog/v13';
  authority_digest: string;
  coverage_universe: CoverageUniverse;
  width_studies: WidthStudy[];
  width_batches: WidthBatch[];
  time_block_plan: TimeBlockPlan;
  materialized_campaigns: MaterializedCampaign[];
  auto_batch_campaigns: AutoBatchCampaign[];
  width_compilations: WidthCompilation[];
  recipes: AuthorityRecipe[];
  native: {
    routes: Array<Record<string, unknown> & { id: string }>;
    treatments: Array<Record<string, unknown> & { id: string }>;
    profiles: Record<string, string[]>;
    authority_path: string;
  };
  targets: AuthorityTarget[];
  lane_registry: AuthorityLaneRegistry;
  performance_profiles: PerformanceProfiles;
  toolchains: AuthorityToolchain[];
  toolchain_pack_catalog: ToolchainPackCatalog;
  factors: AuthorityFactor[];
  factor_variants: AuthorityFactorVariant[];
  plans: AuthorityPlan[];
  sources: Record<string, string>;
};

export type AutoBatchCampaignChunk = {
  id: string;
  position: number;
  name: string;
  plan: string;
  plan_sha256: string;
  queue_digest: string;
  executions: number;
  estimated_minutes: number;
  planning_lower_minutes: number;
  planning_upper_minutes: number;
  source_ids: string[];
  route_ids: string[];
  plan_integrity: 'verified' | 'drifted';
  queue_registered: boolean;
  queue_position: number | null;
};

export type AutoBatchCampaign = {
  schema_version: 'fidb-auto-batch-campaign/v1';
  builder_version: string;
  id: string;
  state: 'generated-disarmed';
  time_model: string;
  time_plan_digest: string;
  source_queue_sha256: string;
  performance_profile: string;
  queue: string;
  campaign_digest: string;
  authority_path: string;
  authority_sha256: string;
  queue_integrity: 'verified-disarmed' | 'drifted';
  policy: {
    target_minutes: number;
    max_minutes: number;
    uncertainty_fraction: number;
    atomic_unit: string;
    packing: string;
    scheduled_chaining: boolean;
    finish_started_chunk: boolean;
  };
  summary: {
    chunks: number;
    libraries: number;
    route_bundles: number;
    executions: number;
    estimated_hours: number;
    planning_lower_hours: number;
    planning_upper_hours: number;
  };
  chunks: AutoBatchCampaignChunk[];
  readiness: {
    verified_plans: number;
    registered_chunks: number;
    queue_disarmed: boolean;
    scheduled_chaining: boolean;
    ready: boolean;
  };
};

export type MaterializedCampaignBlock = {
  id: string;
  position: number;
  state: 'materialized-disarmed';
  plan: string;
  plan_sha256: string;
  queue_digest: string;
  executions: number;
  estimated_hours: number;
  planning_lower_hours: number;
  planning_upper_hours: number;
  source_ids: string[];
  recipe_ids: string[];
  plan_integrity: 'verified' | 'drifted';
  queue_registered: boolean;
  queue_position: number | null;
};

export type MaterializedCampaign = {
  schema_version: 'fidb-materialized-campaign/v1';
  id: string;
  label: string;
  state: 'queued-disarmed' | 'queued-armed' | 'materialization-drifted';
  language_id: string;
  time_model: string;
  time_plan_digest: string;
  performance_profile: string;
  output_directory: string;
  materialization_digest: string;
  authority_path: string;
  authority_sha256: string;
  summary: {
    blocks: number;
    libraries: number;
    executions: number;
    estimated_hours: number;
    planning_lower_hours: number;
    planning_upper_hours: number;
  };
  source_digests: Record<string, string>;
  blocks: MaterializedCampaignBlock[];
  readiness: {
    verified_plans: number;
    registered_blocks: number;
    queue_armed: boolean;
    ready: boolean;
  };
};

export type TimeBlockWorkItem = {
  batch_id: string;
  batch_authority: string;
  source_id: string;
  label: string;
  version: string;
  rank: number;
  executions: number;
  android_executions: number;
  weighted_cells: number;
  source_lines: number;
  complexity_factor: number;
  estimated_hours: number;
  planning_lower_hours: number;
  planning_upper_hours: number;
};

export type TimeBlock = {
  id: string;
  position: number;
  state: 'draft-disarmed';
  estimated_hours: number;
  planning_lower_hours: number;
  planning_upper_hours: number;
  expected_start_local: string;
  expected_nominal_end_local: string;
  executions: number;
  android_executions: number;
  items: TimeBlockWorkItem[];
};

export type TimeBlockPlan = {
  schema_version: 'fidb-time-block-plan/v1';
  id: string;
  label: string;
  state: 'draft-disarmed';
  language_id: string;
  authority_path: string;
  plan_digest: string;
  performance_profile: PerformanceProfile;
  reference: {
    evidence_path: string;
    case_id: string;
    workers: number;
    cells_per_wall_hour: number;
    worker_scaling_exponent: number;
    estimated_cells_per_wall_hour: number;
  };
  policy: {
    target_block_hours: number;
    max_block_hours: number;
    uncertainty_fraction: number;
    packing: string;
    refresh: string;
    freeze: string;
  };
  summary: {
    campaign_batches: number;
    libraries: number;
    blocks: number;
    executions: number;
    android_executions: number;
    estimated_hours: number;
    planning_lower_hours: number;
    planning_upper_hours: number;
  };
  blocks: TimeBlock[];
  source_digests: Record<string, string>;
};

export type PlanDraftResult = {
  schema_version: string;
  path?: string;
  toml_sha256: string;
  previous_sha256?: string | null;
  resolved: {
    plan_digest: string;
    summary: Record<string, number>;
    inventory: AuthorityPlan['inventory'];
  };
};

type Health = {
  status: 'ok';
  coordinator: { state: 'ready' | 'not-initialized' };
};

type EventPage = {
  events: CoordinatorEvent[];
  next_cursor: number;
  has_more: boolean;
};

type ApiErrorBody = { error?: { code?: string; message?: string } };

const maxEventHistory = 500;
const eventPageSize = 200;
const capabilityRefreshMilliseconds = 60_000;

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/fidb/${path}`, {
    cache: 'no-store',
    credentials: 'same-origin',
    ...init,
  });
  const document = (await response.json()) as T & ApiErrorBody;
  if (!response.ok) {
    throw new Error(document.error?.message ?? `Coordinator request failed (${response.status})`);
  }
  return document;
}

export function useFactoryApi(pollMilliseconds = 5000) {
  const [connection, setConnection] = useState<ConnectionState>('connecting');
  const [snapshot, setSnapshot] = useState<CoordinatorSnapshot | null>(null);
  const [capabilities, setCapabilities] = useState<FactoryCapabilities | null>(null);
  const [authority, setAuthority] = useState<FactoryAuthority | null>(null);
  const [laneInventory, setLaneInventory] = useState<LaneInventory | null>(null);
  const [events, setEvents] = useState<CoordinatorEvent[]>([]);
  const [timings, setTimings] = useState<TimingSnapshot | null>(null);
  const [preflight, setPreflight] = useState<OperationsPreflight | null>(null);
  const [timingsError, setTimingsError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const hasSuccessfulRead = useRef(false);
  const refreshInFlight = useRef(false);
  const eventCursor = useRef(0);
  const eventHistory = useRef<CoordinatorEvent[]>([]);
  const capabilityCache = useRef<FactoryCapabilities | null>(null);
  const authorityCache = useRef<FactoryAuthority | null>(null);
  const lastCapabilityRead = useRef(0);

  const resetEvents = useCallback(() => {
    eventCursor.current = 0;
    eventHistory.current = [];
    setEvents([]);
  }, []);

  const refreshEvents = useCallback(async (current: CoordinatorSnapshot) => {
    if (current.last_event_id === 0) {
      resetEvents();
      return;
    }

    let cursor = eventCursor.current;
    let history = eventHistory.current;
    if (cursor > current.last_event_id) {
      cursor = 0;
      history = [];
    }
    if (history.length === 0) {
      cursor = Math.max(0, current.last_event_id - maxEventHistory);
    }

    let pages = 0;
    while (cursor < current.last_event_id && pages < 4) {
      const page = await json<EventPage>(
        `events?after=${cursor}&limit=${eventPageSize}`,
      );
      if (page.next_cursor < cursor) {
        throw new Error('Coordinator event cursor moved backwards');
      }
      if (page.events.length) {
        const merged = new Map(history.map(event => [event.event_id, event]));
        for (const event of page.events) merged.set(event.event_id, event);
        history = [...merged.values()]
          .sort((left, right) => left.event_id - right.event_id)
          .slice(-maxEventHistory);
      }
      if (page.next_cursor === cursor) break;
      cursor = page.next_cursor;
      pages += 1;
      if (!page.has_more) break;
    }

    eventCursor.current = cursor;
    eventHistory.current = history;
    setEvents(history);
  }, [resetEvents]);

  const refresh = useCallback(async (forceCapabilities = false) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    try {
      const health = await json<Health>('health');
      if (
        forceCapabilities
        || capabilityCache.current === null
        || Date.now() - lastCapabilityRead.current >= capabilityRefreshMilliseconds
      ) {
        const [capabilityResult, authorityResult, laneInventoryResult] = await Promise.all([
          json<FactoryCapabilities>('capabilities'),
          json<FactoryAuthority>('authority'),
          json<LaneInventory>('lane-inventory'),
        ]);
        capabilityCache.current = capabilityResult;
        authorityCache.current = authorityResult;
        lastCapabilityRead.current = Date.now();
        setCapabilities(capabilityResult);
        setAuthority(authorityResult);
        setLaneInventory(laneInventoryResult);
      }
      if (health.coordinator.state === 'ready') {
        const [snapshotResult, timingResult, preflightResult] = await Promise.all([
          json<CoordinatorSnapshot>('snapshot?detail=control-panel'),
          json<TimingSnapshot>('timings?limit=200')
            .then(value => ({ value, error: null }))
            .catch(caught => ({
              value: null,
              error: caught instanceof Error ? caught.message : 'Timing API unavailable',
            })),
          json<OperationsPreflight>('preflight'),
        ]);
        setSnapshot(snapshotResult);
        setPreflight(preflightResult);
        setTimings(timingResult.value);
        setTimingsError(timingResult.error);
        await refreshEvents(snapshotResult);
      } else {
        setSnapshot(null);
        setTimings(null);
        setPreflight(null);
        setTimingsError(null);
        resetEvents();
      }
      hasSuccessfulRead.current = true;
      setConnection('live');
      setError(null);
      setLastUpdated(new Date());
    } catch (caught) {
      setConnection(hasSuccessfulRead.current ? 'stale' : 'offline');
      setError(caught instanceof Error ? caught.message : 'Coordinator API unavailable');
    } finally {
      refreshInFlight.current = false;
    }
  }, [refreshEvents, resetEvents]);

  useEffect(() => {
    const kickoff = window.setTimeout(() => void refresh(false), 0);
    const timer = window.setInterval(() => void refresh(false), pollMilliseconds);
    return () => {
      window.clearTimeout(kickoff);
      window.clearInterval(timer);
    };
  }, [pollMilliseconds, refresh]);

  const mutate = useCallback(
    async (action: 'sync' | 'pause' | 'resume', body: Record<string, unknown> = {}) => {
      setBusyAction(action);
      try {
        await json<Record<string, unknown>>(action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        await refresh(false);
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : 'Coordinator mutation failed');
      } finally {
        setBusyAction(null);
      }
    },
    [refresh],
  );

  const planDraft = useCallback(
    async (
      action: 'resolve' | 'save',
      body: Record<string, unknown>,
    ): Promise<PlanDraftResult> => {
      const busy = `plan-draft-${action}`;
      setBusyAction(busy);
      try {
        const result = await json<PlanDraftResult>(`plan-drafts/${action}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        setError(null);
        if (action === 'save') {
          authorityCache.current = null;
          await refresh(true);
        }
        return result;
      } catch (caught) {
        const message = caught instanceof Error ? caught.message : 'Plan draft failed';
        setError(message);
        throw caught;
      } finally {
        setBusyAction(null);
      }
    },
    [refresh],
  );

  return {
    connection,
    snapshot,
    capabilities,
    authority,
    laneInventory,
    events,
    timings,
    preflight,
    timingsError,
    eventHistoryLimited: Boolean(snapshot && snapshot.last_event_id > events.length),
    error,
    busyAction,
    lastUpdated,
    refresh: () => refresh(true),
    sync: () => mutate('sync'),
    pause: (reason: string) => mutate('pause', { reason }),
    resume: () => mutate('resume'),
    resolvePlanDraft: (toml: string) => planDraft('resolve', { toml }),
    savePlanDraft: (name: string, toml: string, expectedSha256?: string) => planDraft(
      'save',
      {
        name,
        toml,
        ...(expectedSha256 ? { expected_sha256: expectedSha256 } : {}),
      },
    ),
  };
}
