'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

import { settlePanelRead } from './panel-health.mjs';

export type ConnectionState = 'connecting' | 'live' | 'stale' | 'offline';

export type PanelReadKey =
  | 'authority'
  | 'capabilities'
  | 'ecological-validation'
  | 'events'
  | 'export'
  | 'fid-matching-backend'
  | 'hash-analysis-backend'
  | 'lane-inventory'
  | 'machine-validation/run'
  | 'noisy-hashes'
  | 'preflight'
  | 'retention'
  | 'snapshot'
  | 'timings'
  | 'validation-observatory';

type PanelReadResult<T> = {
  key: PanelReadKey;
  value: T | null;
  error: string | null;
};

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
  result_jobs_total?: number;
  result_jobs_included?: number;
  result_jobs_truncated?: boolean;
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
  linked_reference?: {
    schema_version: 'fidb-linked-reference-performance-resolution/v1';
    state: 'ready' | 'blocked';
    mode: 'auto' | 'fixed';
    authority_path: string;
    authority_sha256: string;
    host: {
      physical_cores: number;
      logical_cpus: number;
      total_memory_mib: number;
      available_memory_mib: number;
    };
    selected_profile: null | {
      id: string;
      workers: number;
      jvm_max_heap_mib: number;
      jvm_active_processors: number;
      qualification: string;
      guidance: string;
    };
    profiles: Array<{
      id: string;
      workers: number;
      qualification: string;
      eligible: boolean;
      blockers: string[];
    }>;
    blockers: string[];
  };
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
  qualification: QualificationGate;
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
    qualification_state: string;
    qualification_satisfied: boolean;
    queue_eligible_executions: number;
    queue_state: string;
    blockers: string[];
  };
};

export type QualificationGate = {
  batch_id: string;
  batch_digest: string;
  state: 'qualified' | 'required' | 'incomplete' | 'failed' | 'stale' | 'invalid' | 'blocked' | 'authority-required' | 'historical-exempt' | 'legacy-exemption-stale' | string;
  satisfied: boolean;
  promotion_state: 'queue-eligible-disarmed' | 'historical-sealed' | 'blocked' | string;
  authority_path: string | null;
  authority_sha256?: string;
  pipeline_authority_path?: string;
  pipeline_authority_sha256?: string;
  input_digest?: string;
  qualification_digest: string | null;
  evidence_path: string | null;
  evidence_sha256: string | null;
  summary: {
    total: number;
    built: number;
    failed: number;
    remaining: number;
  };
  blockers: string[];
  reason?: string;
};

export type QualificationPipeline = {
  schema_version: 'fidb-qualification-pipeline-status/v1';
  state: 'enforced';
  authority_path: string;
  authority_sha256: string;
  policy: {
    require_current_seal_before_materialization: boolean;
    embed_seal_in_generated_plans: boolean;
    require_full_path_canary_after_materialization: boolean;
    automatic_arming: boolean;
    promotion_state: 'queue-eligible-disarmed';
  };
  summary: {
    batches: number;
    satisfied: number;
    blocked: number;
    qualified: number;
    historical_exempt: number;
  };
  gates: QualificationGate[];
};

export type CampaignProgrammeCandidate = {
  rank: number;
  canonical_key: string;
  display_name: string;
  subject_id: string;
  source_breadth: number;
  popularity_proxy_share_pct: number;
  cumulative_popularity_proxy_pct: number;
  research_source_pinned: boolean;
  research_source_cached: boolean;
  research_source_resolver: string | null;
  research_source_version: string | null;
  research_source_reason: string | null;
  screened: boolean;
  source_pinned: boolean;
  source_cached: boolean;
  recipe_ready: boolean;
  width_batch_bound: boolean;
  width_batch_id: string | null;
  qualification_state: string;
  qualification_satisfied: boolean;
  stage: string;
};

export type CampaignProgrammeCohort = {
  id: string;
  order: number;
  label: string;
  candidate_rank_start: number;
  candidate_rank_end: number;
  capacity: number;
  state: 'planned-disarmed';
  stage: string;
  counts: {
    research_source_pinned: number;
    research_source_cached: number;
    screened: number;
    source_pinned: number;
    source_cached: number;
    recipe_ready: number;
    width_batch_bound: number;
    qualification_satisfied: number;
  };
  planned_qualification_cells: number;
  planned_campaign_executions: number;
  candidates: CampaignProgrammeCandidate[];
};

export type CampaignProgramme = {
  schema_version: 'fidb-campaign-programme-status/v1';
  id: string;
  label: string;
  state: 'planned-disarmed';
  language_id: 'c';
  evidence_class: string;
  caveat: string;
  candidate_cumulative_proxy_pct: number;
  cohort_size: number;
  route_profiles_per_library: number;
  treatments_per_route: number;
  campaign_executions_per_library: number;
  qualification_routes_per_library: number;
  authorities: Record<string, string>;
  pipeline: { stages: string[] } & Record<string, string | string[]>;
  summary: {
    candidate_population: number;
    cohorts: number;
    full_cohorts: number;
    final_cohort_size: number;
    research_source_pinned_candidates: number;
    research_source_cached_candidates: number;
    screened_candidates: number;
    source_pinned_candidates: number;
    source_cached_candidates: number;
    recipe_ready_candidates: number;
    qualification_satisfied_candidates: number;
    planned_qualification_cells: number;
    planned_campaign_executions: number;
  };
  source_acquisition: {
    candidates: number;
    pinned: number;
    receipt_cached: number;
    unresolved: number;
  };
  stage_counts: Record<string, number>;
  cohorts: CampaignProgrammeCohort[];
};

export type CohortValidationStage = {
  id: string;
  label: string;
  state: string;
  detail: string;
};

export type CohortValidationProgramme = {
  id: string;
  label: string;
  cohorts: Array<{
    id: string;
    order: number;
    capacity: number;
    candidate_rank_start: number;
    candidate_rank_end: number;
    state: string;
    work: {
      width_build_cells: number;
      exact_identities: number;
      validation_composites: number;
      query_projections: number;
      fused_ghidra_analyses: number;
      legacy_duplicate_analyses_avoided: number;
    };
    stages: CohortValidationStage[];
  }>;
};

export type CohortValidationLifecycle = {
  schema_version: 'fidb-cohort-validation-lifecycle-status/v1';
  id: string;
  label: string;
  state: 'planned-disarmed';
  language_id: string;
  authority_path: string;
  authority_sha256: string;
  query_evidence_contract: string;
  execution: {
    scientific_boundary: string;
    scheduler_boundary: string;
    folds_per_identity: number;
    query_projections_per_composite: number;
  };
  fusion: {
    enabled_for_new_runs: boolean;
    single_ghidra_analysis_per_composite: boolean;
    canonical_export: string;
    export_roles: string[];
    routine_backfill: string;
    legacy_backfill: string;
  };
  reference_population: {
    routine: 'archive-plus-linked';
    forms: string[];
    linked_input: 'sealed-static-archive';
    compile_source: false;
    link_harness: string;
    population_engine: 'alpha_engine_2';
    promotion_gate: string;
    ablation_populations: string[];
  };
  incremental: {
    primary_confusion_scope: string;
    corpus_noise_scope: string;
    historical_replay: string;
    historical_sentinel_enabled: boolean;
    full_revalidation_milestones: number[];
  };
  scheduling: {
    maximum_unvalidated_width_cohorts: number;
    validation_failure_action: string;
    retention_required_before_admission: boolean;
  };
  admission: {
    automatic_corpus_admission: boolean;
    scientific_threshold_authority: string;
    unconfigured_threshold_action: string;
  };
  performance: {
    estimate_class: string;
    legacy_composite_ghidra_analyses_per_cohort: number;
    legacy_backfill_ghidra_analyses_per_cohort: number;
    fused_ghidra_analyses_per_cohort: number;
    observed_composite_build_wall_hours: number;
    observed_backfill_wall_hours: number;
    observed_gpu_match_wall_hours: number;
    projected_fused_cycle_wall_hours_lower: number;
    projected_fused_cycle_wall_hours_upper: number;
  };
  stages: CohortValidationStage[];
  active_cohort: null | {
    id: string;
    label: string;
    integration: string;
    libraries: number;
    width_state: string;
    validation_state: string;
    admission_state: string;
    result_state: string;
  };
  bound_cohorts: Array<{
    id: string;
    order: number;
    label: string;
    state: string;
    source_pack: string;
    width_batch: string;
    seed: string;
    source_ids: string[];
    fold_a: string[];
    fold_b: string[];
    width_batch_state: string;
    width_queue_eligible_executions: number;
    validation_state: string;
    automatic_materialization: boolean;
    automatic_scheduling: boolean;
  }>;
  programmes: CohortValidationProgramme[];
  summary: {
    programme_cohorts: number;
    planned_validation_composites: number;
    legacy_duplicate_analyses_avoided: number;
    bound_future_cohorts: number;
    fused_analyses_per_full_cohort: number;
    legacy_analyses_per_full_cohort: number;
  };
  status_digest: string;
};

export type FactoryAuthority = {
  schema_version: 'fidb-authority-catalog/v19';
  authority_digest: string;
  coverage_universe: CoverageUniverse;
  width_studies: WidthStudy[];
  width_batches: WidthBatch[];
  campaign_programmes: CampaignProgramme[];
  qualification_pipeline: QualificationPipeline;
  time_block_plan: TimeBlockPlan;
  materialized_campaigns: MaterializedCampaign[];
  auto_batch_campaigns: AutoBatchCampaign[];
  machine_validations: MachineValidation[];
  cohort_validation: CohortValidationLifecycle;
  ecological_validation: EcologicalValidation;
  noisy_hashes: NoisyHashStatus;
  hash_discrimination: HashDiscriminationStatus;
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

export type MachineValidationFailure = {
  failure_type: 'collision' | 'miss';
  library_id: string;
  function_id: string;
  route_id: string;
  compiler_id: string;
  treatment_id: string;
  signature: string;
  candidate_owner: string;
  evidence_path: string;
};

export type MachineValidationRun = {
  schema_version?: 'fidb-machine-validation-run-status/v1';
  validation_id?: string;
  run_id: string | null;
  mode: 'canary' | 'full' | null;
  state: 'not-started' | 'queued' | 'preparing-index' | 'running' | 'pausing' | 'paused' | 'interrupted' | 'postprocessing' | 'postprocess-failed' | 'retaining' | 'complete' | 'failed' | 'invalid';
  pid?: number | null;
  worker_pids?: number[];
  started_at?: string | null;
  finished_at?: string | null;
  paused_at?: string | null;
  resumed_at?: string | null;
  resume_count?: number;
  expected_work_units?: number;
  complete_work_units: number;
  failed_work_units: number;
  report_path?: string;
  error?: string;
  postprocess_job?: {
    id: string;
    kind: string;
    state: string;
    materialized_with_batch?: boolean;
    required_for_run_completion: boolean;
    stages: Array<{ id: string; state: string }>;
  };
};

export type MachineValidationCanaryGate = {
  ready: boolean;
  state: 'passed' | 'not-run' | 'stale-or-failed';
  run_id: string | null;
  report_path: string | null;
  runtime_authority_sha256: string;
};

export type MachineHashSummary = {
  scope: string;
  signature: string;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  unattributed_observations: number;
  distinct_correct_owners: number;
  distinct_incorrect_owners: number;
  distinct_reference_owners: number;
  distinct_routes: number;
  distinct_treatments: number;
};

export type HashComponentDistribution = {
  distinct_owners: number;
  distinct_values: number;
  fraction_of_values: number;
};

export type HashComponentAmbiguity = {
  scope: string;
  language: string;
  value: string;
  distinct_owners: number;
  reference_observations: number;
  exact_signature_variants: number;
  exact_false_positive_observations: number;
  owners: string[];
};

export type HashComponentLibrary = {
  owner: string;
  distinct_values: number;
  multi_owner_values: number;
  ambiguous_fraction: number;
  reference_observations: number;
  missed_observations: number;
  exact_false_positive_observations: number;
};

export type HashNoisePopulation = {
  noisy_values: number;
  noisy_fraction: number | null;
  other_multi_owner_values: number;
  other_multi_owner_fraction: number | null;
  single_owner_values: number;
  single_owner_fraction: number | null;
  false_positive_observations: number;
  false_positive_fraction: number | null;
};

export type HashFalsePositiveConcentrationPoint = {
  rank: number;
  noisy_hash_fraction: number;
  false_positive_fraction: number;
  false_positive_observations: number;
};

export type HashTypeAnalysis = {
  hash_type: 'full' | 'specific' | 'complete';
  distinct_values: number;
  singleton_values: number;
  multi_owner_values: number;
  multi_owner_fraction: number;
  owner_links: number;
  ambiguous_owner_links: number;
  complete_disambiguated_owner_signatures: number;
  reference_observations: number;
  exact_false_positive_observations: number;
  false_positive_values?: number | null;
  maximum_distinct_owners: number;
  noise_population?: HashNoisePopulation;
  false_positive_concentration?: HashFalsePositiveConcentrationPoint[];
  distribution?: HashComponentDistribution[];
  top_ambiguous?: HashComponentAmbiguity[];
  libraries?: HashComponentLibrary[];
};

export type ValidationObservatoryRun = {
  key: string;
  validation_id: string;
  run_id: string;
  finished_at: string;
  report_path: string;
  report_sha256: string;
  source_evidence_sha256: string;
  method_authority?: {
    id: string;
    path?: string;
    sha256: string;
    algorithm_id?: string;
  } | null;
  corpus_index?: {
    state: string;
    ordinal: number;
    generation_digest: string;
    owners: number;
    signatures: number;
    database_path: string;
    authority_sha256: string;
  } | null;
  gpu_comparison?: {
    state: string;
    scope: string;
    report_path: string;
    candidate_backend: string;
    publish_from: string;
    mismatches: number | null;
    performance?: Record<string, number | null>;
  } | null;
  lookup_backend?: {
    selected: string;
    implementation: string;
    device: 'cpu' | 'gpu';
    scope: string;
    requested_mode: 'auto' | 'cpu' | 'gpu';
    fallback_reason: string | null;
  } | null;
  pipeline_job?: {
    id: string;
    kind: string;
    state: string;
    materialized_with_batch: boolean;
    required_for_run_completion: boolean;
    stages: Array<{ id: string; state: string }>;
  };
  construct_validity?: {
    state: string;
    recall_claim: string;
    reference_unit?: string;
    query_unit?: string;
    route_false_negative_rate_spread?: number | null;
    legacy_projection?: boolean;
    by_route?: Array<HashMissStratum>;
    by_treatment?: Array<HashMissStratum>;
    by_owner?: Array<HashMissStratum>;
  };
  confusion_matrix: {
    unit?: string;
    true_positives: number;
    false_positives: number;
    true_negatives: number;
    false_negatives: number;
  };
  rates: {
    true_positive_rate: number | null;
    false_positive_rate: number | null;
    true_negative_rate: number | null;
    false_negative_rate: number | null;
    precision: number | null;
  };
  hash_evidence: Partial<{
    database_path: string;
    database_sha256: string;
    distinct_signatures: number;
    noisy_signatures: number;
    multi_owner_signatures: number;
    missed_signatures: number;
    unattributed_signatures: number;
    query_signature_observations: number;
    unattributed_query_signatures: number;
    fold_results: number;
    top_noisy: MachineHashSummary[];
    top_low_information: MachineHashSummary[];
  }>;
  hash_types: HashTypeAnalysis[];
  performance?: Record<string, number | string>;
};

export type HashMissStratum = {
  id: string;
  true_positives: number;
  false_negatives: number;
  false_negative_rate: number | null;
};

export type ValidationObservatory = {
  schema_version: 'fidb-validation-observatory/v1';
  generated_at: string;
  state: 'ready' | 'awaiting-evidence';
  summary: {
    measured_runs: number;
    validation_cohorts: number;
    method_versions: string[];
  };
  latest_run_key: string | null;
  selected_run_key: string | null;
  selection_found: boolean;
  runs: ValidationObservatoryRun[];
  trends: Array<{
    hash_type: HashTypeAnalysis['hash_type'];
    points: Array<HashTypeAnalysis & { run_key: string; run_id: string; finished_at: string }>;
  }>;
  selected: (ValidationObservatoryRun & {
    hash_type_analysis: HashTypeAnalysis[];
    failures: MachineValidationFailure[];
    decision_contract?: Record<string, string>;
  }) | null;
};

export type HashAnalysisBackendStatus = {
  schema_version: 'fidb-hash-backend-status/v1';
  authority_path: string;
  authority_sha256: string;
  requested_mode: 'auto' | 'cpu' | 'gpu';
  effective_backend: {
    id: string;
    state: string;
    implementation: string;
    device: 'cpu' | 'gpu';
    scope: string;
  };
  fallback_reason: string | null;
  performance: {
    schema_version: string;
    mode: 'auto' | 'cpu' | 'gpu';
    allow_gpu: boolean;
    fallback_to_cpu: boolean;
    authority_path: string;
    authority_sha256: string;
  };
  gpu: {
    allowed: boolean;
    runtime_available: boolean;
    authoritative: boolean;
    wgpu_installed: boolean;
    detected_devices: Array<{ name: string; vendor_id: string; device_id: string }>;
    backend: Record<string, unknown> | null;
    qualification: {
      state?: string;
      report_path: string;
      report_sha256?: string;
      mismatches?: number;
      device?: Record<string, unknown>;
      performance?: Record<string, number | null>;
    } | null;
  };
  backends: Array<Record<string, unknown>>;
};

export type FidMatchingBackendStatus = {
  schema_version: 'fidb-fid-matching-backend-status/v1';
  requested_mode: 'auto' | 'cpu' | 'gpu';
  requested_backend: string;
  effective_backend: {
    id: string;
    state: string;
    implementation: string;
    device: 'cpu' | 'gpu';
    scope: string;
  };
  fallback_reason: string | null;
  performance: {
    schema_version: string;
    mode: 'auto' | 'cpu' | 'gpu';
    allow_gpu: boolean;
    fallback_to_cpu: boolean;
    candidate_chunk_rows: number;
    workgroup_size: number;
    authority_path: string;
    authority_sha256: string;
  };
  gpu: {
    allowed: boolean;
    runtime_available: boolean;
    authoritative: boolean;
    wgpu_installed: boolean;
    detected_devices: Array<{ name: string; vendor_id: string; device_id: string }>;
    backend: Record<string, unknown> | null;
    qualification: {
      state: string;
      decision_mismatches: number | null;
      truth_coverage: number | null;
      backend: {
        requested?: string;
        effective?: string[];
        fallback_cases?: string[];
        contract_met?: boolean;
      };
    };
  };
  backends: Array<Record<string, unknown>>;
};

export type MachineValidationLive = {
  run: MachineValidationRun;
  canary_gate: MachineValidationCanaryGate;
  fid_matching: FidMatchingCampaign;
};

export type FidMatchingCampaignReport = {
  state: 'qualified' | 'measured-complete' | 'incomplete-or-failed';
  progress: { expected_cases: number; complete_cases: number; failed_or_pending_cases: number };
  oracle: { decision_mismatches: number; canary_passed: boolean | null };
  truth: { labelled_functions: number; unlabelled_functions: number; coverage: number };
  confusion_matrix: {
    true_positives: number;
    false_positives: number;
    true_negatives: number;
    false_negatives: number;
  };
};

export type FidMatchingCampaign = {
  schema_version: 'fidb-fid-matching-campaign-status/v1';
  id: string;
  state: string;
  mode: 'canary' | 'full' | null;
  started_at: string | null;
  finished_at: string | null;
  source_run_id: string;
  workers: number;
  schedule: {
    timezone: string;
    window: Array<{ id: string; days: string[]; start: string; stop_admitting: string; enabled: boolean }>;
  };
  methodology: {
    decision_unit: string;
    candidate_semantics: string;
    truth_precedence: string[];
    retain_hash_types: string[];
  };
  qualification: {
    state: string;
    case?: { route_id: string; treatment_id: string };
    oracle?: { functions: number; candidate_rows: number; accepted_functions: number };
    classification?: {
      decision_unit: string;
      labelled_functions: number;
      unlabelled_functions: number;
      true_positives: number;
      false_positives: number;
      true_negatives: number;
      false_negatives: number;
    };
    backends?: Array<{
      id: string;
      device: string;
      decision_mismatches: number;
      maximum_score_float32_ulps: number;
      wall_time_ns: number;
    }>;
  };
  canary: FidMatchingCampaignReport;
  full: FidMatchingCampaignReport;
};

export type MachineValidation = {
  schema_version: 'fidb-machine-validation-status/v1';
  id: string;
  label: string;
  state: 'waiting-for-cohort' | 'eligible-disarmed';
  language_id: string;
  batch_kind: 'validation-run';
  authority_path: string;
  status_digest: string;
  run: MachineValidationRun;
  canary_gate: MachineValidationCanaryGate;
  fid_matching: FidMatchingCampaign;
  randomization: {
    method: string;
    algorithm: string;
    seed: string;
    canonical_ids: string[];
    fold_a: string[];
    fold_b: string[];
  };
  cohort_policy: {
    nominal_size: number;
    minimum_final_partial_size: number;
    final_partial_override: boolean;
    final_partial_justification: string;
    split_policy: string;
  };
  batch: {
    automatic_materialization: boolean;
    automatic_scheduling: boolean;
    scheduler_registry: string;
    production_queue_mutation: boolean;
    first_run_requires_canary: boolean;
    input_strategy: string;
    harness_mode: string;
    execute_target_binaries: boolean;
    truth_copy: string;
    query_copy: string;
    exact_inclusion_sanity: string;
    trigger: string;
    output_root: string;
  };
  queries: { primary_projections: string[] };
  metrics: { required: string[] };
  hash_discrimination_job: {
    id: string;
    kind: string;
    automatic: boolean;
    required_for_run_completion: boolean;
    method_authority: string;
    corpus_authority: string;
    backend_authority: string;
    stages: string[];
    outputs: string[];
  };
  planning: {
    estimate_class: string;
    central_wall_hours: number;
    lower_wall_hours: number;
    upper_wall_hours: number;
    safe_ram_gib_lower: number;
    safe_ram_gib_upper: number;
    scratch_headroom_gib_lower: number;
    scratch_headroom_gib_upper: number;
    raw_retained_gib_lower: number;
    raw_retained_gib_upper: number;
    compact_output_gib_upper: number;
  };
  ecological_validation: {
    state: 'final-dataset-only';
    included_in_validation_batch: false;
    gate: string;
    mode: string;
  };
  summary: {
    cohort_libraries: number;
    complete_libraries: number;
    exact_identities: number;
    baseline_exact_identities: number;
    width_delta_from_baseline: number;
    completed_exact_inputs: number;
    required_exact_inputs: number;
    work_units: number;
    composite_programs: number;
    query_projections: number;
  };
  readiness: {
    eligible: boolean;
    materializable: boolean;
    queue_state: string;
    execution_state: string;
    blockers: string[];
  };
  libraries: Array<{
    id: string;
    fold: 'A' | 'B';
    state: 'complete' | 'building' | 'not-started';
    completed_exact_identities: number;
    required_exact_identities: number;
    missing_exact_identities: number;
  }>;
  stages: Array<{ id: string; label: string; state: string; detail: string }>;
  results: {
    state: 'not-run' | 'invalid-report' | 'measured-complete';
    report_path: string | null;
    detail?: string;
    confusion_matrix: {
      unit: 'complete-fid-signature-owner-assertion';
      true_positives: number | null;
      false_positives: number | null;
      true_negatives: number | null;
      false_negatives: number | null;
    };
    failure_summary: { collisions: number; misses: number };
    failures: MachineValidationFailure[];
    hash_evidence?: {
      database_path: string;
      database_sha256: string;
      distinct_signatures: number;
      noisy_signatures: number;
      multi_owner_signatures: number;
      missed_signatures: number;
      unattributed_signatures: number;
      query_signature_observations: number;
      unattributed_query_signatures: number;
      fold_results: number;
      top_noisy: MachineHashSummary[];
      top_low_information: MachineHashSummary[];
    };
  };
};

export type EcologicalFailure = {
  failure_type: 'collision' | 'miss';
  owner: string;
  address: string;
  target_function: string;
  corpus_function: string;
  signature: string;
  route_id: string;
  compiler_id: string;
  treatment_id: string;
  evidence_path: string;
};

export type EcologicalConfusion = {
  unit: 'imported-binary-corpus-library-presence';
  true_positives: number | null;
  false_positives: number | null;
  true_negatives: number | null;
  false_negatives: number | null;
};

export type EcologicalCase = {
  case_id: string;
  label: string;
  state: 'imported' | 'queued' | 'running' | 'complete' | 'failed';
  created_at: string;
  updated_at: string;
  binary: {
    original_filename: string;
    stored_path: string;
    bytes: number;
    sha256: string;
    never_execute: true;
  };
  platform_hint: string;
  truth: {
    expected_present: string[];
    expected_absent: string[];
    complete: boolean;
  };
  probe: {
    state: string;
    binary_format: string;
    platform?: string;
    architecture?: string;
    bits?: number;
    endianness?: string;
    target_id: string | null;
    lane_id: string | null;
    sublane_id: string | null;
    ghidra_language_id?: string | null;
    ghidra_compiler_spec_id?: string | null;
    blocker?: string | null;
  };
  run: {
    started_at: string | null;
    finished_at: string | null;
    error: string | null;
    pid: number | null;
  };
  readiness: {
    ready_to_run: boolean;
    blockers: string[];
    corpus_generations: number;
  };
  corpus: Array<{
    path: string;
    generation_id: string;
    lane_id: string;
    kind: string;
    state: string;
    bytes: number;
    raw_observations: number;
    unique_signatures: number | null;
  }>;
  results: {
    state: 'not-run' | 'invalid-report' | 'measured-complete';
    confusion_matrix: EcologicalConfusion;
    failure_summary: { collisions: number; misses: number };
    failures: EcologicalFailure[];
    owner_matches: Array<{
      owner: string;
      matched_functions: number;
      matched_occurrences: number;
      truth: 'present' | 'absent' | 'unlabelled';
      evidence: EcologicalFailure[];
    }>;
    report_path: string | null;
    metrics?: Record<string, number | string | null>;
    failure_rows_truncated?: number;
    owner_rows_truncated?: number;
  };
};

export type EcologicalValidation = {
  schema_version: 'fidb-ecological-validation-status/v1';
  id: string;
  label: string;
  state: string;
  authority_path: string;
  authority_sha256: string;
  status_digest: string;
  policy: {
    corpus_scope: string;
    generation_policy: string;
    analysis_engine: string;
    decision_unit: string;
    never_execute: true;
    max_file_bytes: number;
  };
  corpus: {
    materialized_generations: number;
    active_packs: number;
    bytes: number;
    raw_observations: number;
    compact_unique_signatures: number;
    issues: number;
  };
  summary: {
    imported_cases: number;
    ready_cases: number;
    running_cases: number;
    completed_cases: number;
    labelled_cases: number;
  };
  aggregate: {
    measured_cases: number;
    confusion_matrix: EcologicalConfusion;
    failure_summary: { collisions: number; misses: number };
    failures: EcologicalFailure[];
  };
  cases: EcologicalCase[];
};

export type NoisyHashEvidence = {
  source: 'machine' | 'ecological';
  run_id: string;
  owner: string;
  library_id: string;
  function_id: string;
  route_id: string;
  compiler_id: string;
  treatment_id: string;
  evidence_path: string;
};

export type NoisyHashRow = {
  signature_id: string;
  scope: string;
  signature: string;
  classification: 'candidate-noisy' | 'confirmed-noisy';
  risk: 'review' | 'high';
  disposition: 'observe' | 'quarantine' | 'reviewed-shared' | 'cleared';
  collisions: number;
  distinct_runs: number;
  distinct_owners: number;
  owners: string[];
  sources: string[];
  decision: Record<string, string> | null;
  evidence: NoisyHashEvidence[];
  evidence_rows_truncated: number;
};

export type NoisyHashStatus = {
  schema_version: 'fidb-noisy-hash-status/v1';
  id: string;
  label: string;
  state: string;
  authority_path: string;
  authority_sha256: string;
  status_digest: string;
  classification: {
    candidate_min_collisions: number;
    confirmed_min_collisions: number;
    confirmed_min_distinct_runs: number;
    high_risk_min_distinct_owners: number;
    grouping_key: string;
  };
  management: {
    default_state: string;
    allowed_states: Array<'observe' | 'quarantine' | 'reviewed-shared' | 'cleared'>;
    quarantine_effect: string;
    automatic_deletion: false;
    require_reason: true;
  };
  summary: {
    observed_hashes: number;
    returned_hashes: number;
    hash_rows_truncated: number;
    candidate_noisy: number;
    confirmed_noisy: number;
    quarantined: number;
    reviewed_shared: number;
    cleared: number;
    reports_scanned: number;
    evidence_databases_scanned: number;
  };
  hashes: NoisyHashRow[];
};

export type HashDiscriminationComponent = {
  id: string;
  label: string;
  weight_percent: number;
  calculation: string;
};

export type HashDiscriminationScore = {
  score_id: string;
  scope: string;
  signature: string;
  candidate_owner: string;
  generation_id: string;
  hdi: number;
  noise_risk: number;
  confidence: number;
  evidence_sufficiency: string;
  reason_category: string;
  reason_confidence: number | null;
  components: Record<string, number>;
};

export type HashDiscriminationStatus = {
  schema_version: 'fidb-hash-discrimination-status/v1';
  id: string;
  label: string;
  state: 'awaiting-c10-evidence' | 'ready-for-first-fit';
  authority_path: string;
  authority_sha256: string;
  status_digest: string;
  identity: {
    analyst_term: string;
    grouping_key: string;
    score_scope: string;
    pool_incompatible_sublanes: false;
  };
  index: {
    name: 'Hash Discrimination Index';
    abbreviation: 'HDI';
    minimum: 0;
    maximum: 100;
    higher_means: string;
    is_probability: false;
  };
  noise_risk: {
    name: string;
    minimum: 0;
    maximum: 100;
    higher_means: string;
    independent_from_hdi: true;
  };
  model: {
    kind: string;
    state: string;
    complex_learning_allowed_at_c10: false;
    forward_evaluation: true;
    hdi_formula: string;
    noise_risk_formula: string;
    component_value_minimum: number;
    component_value_maximum: number;
    smoothing_alpha: number;
    smoothing_beta: number;
  };
  reproducibility: {
    algorithm_id: string;
    deterministic_order: string;
    randomness: string;
    floating_point: string;
    rounding_decimal_places: number;
    source_digest_policy: string;
    code_revision_required: true;
    generation_write_policy: string;
  };
  safety: {
    automatic_filtering: false;
    automatic_admission_mutation: false;
    missing_measurements: string;
    immutable_generations: true;
    preserve_unweighted_baseline: true;
    require_heldout_ecological_gate: true;
    preserve_raw_observations: true;
  };
  reason_categories: string[];
  readiness: {
    ready_for_first_fit: boolean;
    required_library_families: number;
    complete_library_families: number;
    materialized_lane_generations: number;
    raw_observations: number;
    compact_unique_signatures: number;
    machine_validation_state: string;
    ecological_measured_cases: number;
    blockers: string[];
  };
  signals: Array<{
    id: string;
    label: string;
    requirement: string;
    required: boolean;
    state: string;
    measurement: number | null;
  }>;
  hdi_components: HashDiscriminationComponent[];
  noise_components: HashDiscriminationComponent[];
  treatments: Array<{
    id: string;
    label: string;
    mode: string;
    required: true;
    state: string;
    precision: number | null;
    recall: number | null;
    false_positive_rate: number | null;
    abstention_rate: number | null;
    incorrect_confident_attributions: number | null;
  }>;
  generations: Array<{
    id: string;
    cohort_library_families: number;
    role: string;
    state: string;
    scored_signatures: number | null;
    published_at: string | null;
  }>;
  summary: {
    scored_signatures: number | null;
    high_discrimination: number | null;
    context_only: number | null;
    ambiguous_or_shared: number | null;
    demonstrated_harmful: number | null;
    unclassified: number | null;
    observed_collision_signatures: number;
  };
  scores: HashDiscriminationScore[];
  noisy_hashes: {
    state: string;
    status_digest: string;
    summary: NoisyHashStatus['summary'];
  };
  corpus_index: {
    schema_version: 'fidb-corpus-hash-index/v1';
    state: 'not-built' | 'empty' | 'ready';
    database_path: string;
    database_sha256?: string;
    database_bytes?: number;
    authority_sha256: string;
    generation?: {
      ordinal: number;
      generation_digest: string;
      owners: number;
      signatures: number;
      query_observations: number;
      true_positives: number;
      false_positives: number;
      true_negatives: number;
      false_negatives: number;
    } | null;
  };
};

export type RetentionPlanSummary = {
  verified_successes: number;
  actions: number;
  failure_bundles: number;
  success_scratch_prunes: number;
  verified_validation_runs: number;
  validation_scratch_prunes: number;
  validation_composite_prunes: number;
  validation_composite_files: number;
  validation_source_directories: number;
  validation_recoverable_apparent_bytes: number;
  source_directories: number;
  recoverable_apparent_bytes: number;
  recoverable_allocated_bytes: number;
  preserved: number;
  quarantined: number;
};

export type ExportStatus = {
  schema_version: 'fidb-export-status/v1';
  authority: {
    id: string;
    label: string;
    path: string;
    sha256: string;
  };
  release: {
    id: string;
    language_id: string;
    package_format: string;
    output_path: string;
    exists: boolean;
    bytes: number;
    sha256: string | null;
  };
  population: {
    expected: number;
    present: number;
    missing: number;
    libraries_expected: number;
    libraries_complete: number;
    routes: number;
    treatments: number;
    raw_bytes: number;
    duplicate_completed_identities: number;
    unexpected: number;
  };
  libraries: Array<{
    id: string;
    label: string;
    version: string;
    rank: number;
    present: number;
    expected: number;
    missing: number;
    complete: boolean;
    bytes: number;
  }>;
  missing_examples: string[];
  hash_quality: {
    state: string;
    path?: string;
    bytes?: number;
    sha256?: string | null;
    error?: string;
    generation?: {
      ordinal: number;
      digest: string;
      owners: number;
      signatures: number;
      query_observations: number;
      true_positives: number;
      false_positives: number;
      true_negatives: number;
      false_negatives: number;
    };
  };
  validation: { state: string; path: string; bytes: number };
  compatibility: { state: string; path: string };
  safeguard: {
    state: 'missing' | 'stale' | 'invalid' | 'current';
    required: boolean;
    receipt_path: string;
    ledger_snapshot_path: string;
    retention_authority_path: string;
    population_sha256: string;
    artifact_count: number;
    raw_artifact_bytes: number;
    live_jobs: number;
    receipt_sha256: string | null;
    created_at: string | null;
    error: string | null;
  };
  blockers: string[];
  ready: boolean;
  actions: { preview: boolean; safeguard: boolean; build: boolean };
  build?: {
    state: string;
    built_at: string;
    path: string;
    bytes: number;
    sha256: string;
    checksum_path: string;
    members: number;
  };
};

export type RetentionStatus = {
  schema_version: 'fidb-retention-status/v1';
  policy: {
    schema_version: string;
    name: string;
    authority_path: string;
    authority_sha256: string;
    paths: Record<string, string>;
    success: {
      preserve_until_lane_imported: boolean;
      prune_after_receipt: string[];
      required_result_artifacts: string[];
    };
    failure: {
      retain_latest_evidence_bundle: boolean;
      collapse_identical_retries: boolean;
      evidence_globs: string[];
      max_evidence_file_bytes: number;
    };
    validation: {
      enabled: boolean;
      automatic_after_terminal_run: boolean;
      scratch_globs: string[];
      required_fold_artifacts: string[];
      prune_composite_binaries: boolean;
      required_signature_evidence_schema: string;
    };
    automation: {
      enabled: boolean;
      triggers: string[];
      mode: string;
      dry_run_first: boolean;
      maximum_estimated_seconds: number;
      worker_action: string;
    };
    memory_cleanup: {
      enabled: boolean;
      audit_after_recycle: boolean;
      post_recycle_rss_warning_mib: number;
      park_terminal_workers: boolean;
      park_poll_seconds: number;
    };
    limits: Record<string, number>;
  };
  latest_plan: null | {
    plan_digest: string;
    path: string;
    generated_at: string;
    scope: string;
    trigger: string;
    summary: RetentionPlanSummary;
    scan_duration_ns: number;
    estimated_apply_seconds: number;
    automatic_apply_eligible: boolean;
    preserved_examples: Array<Record<string, unknown>>;
    quarantine_examples: Array<Record<string, unknown>>;
    action_examples: Array<Record<string, unknown>>;
  };
  last_run: null | {
    state: string;
    mode: string;
    plan_digest: string;
    session_id: string;
    scope: string;
    trigger: string;
    started_at: string;
    completed_at: string;
    duration_ns: number;
    actions_completed: number;
    removed: {
      files: number;
      directories: number;
      apparent_bytes: number;
      allocated_bytes: number;
    };
    bundle_bytes: number;
    filesystem_free_bytes_delta: number;
  };
  memory_cleanup: {
    enabled: boolean;
    audit_after_recycle: boolean;
    post_recycle_rss_warning_bytes: number;
    latest_session: null | {
      session_id?: string;
      recorded_at?: string;
      workers?: number;
      passed?: number;
      warnings?: number;
      unreadable_reports: number;
      before_rss_bytes?: number;
      after_rss_bytes?: number;
      reclaimed_rss_bytes?: number;
      reports?: Array<{
        state: 'passed' | 'warning' | 'disabled';
        worker_id: string;
        recorded_at: string;
        before: { rss_bytes: number; embedded_jvm_started: boolean | null };
        after: { rss_bytes: number; embedded_jvm_started: boolean | null };
        reclaimed_rss_bytes: number;
        reasons: string[];
      }>;
    };
  };
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
  qualification_gates?: QualificationGate[];
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
  qualification_gates?: QualificationGate[];
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
const capabilityRefreshMilliseconds = 15 * 60_000;
const idlePollMilliseconds = 30_000;

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

async function panelJson<T>(key: PanelReadKey, path: string): Promise<PanelReadResult<T>> {
  return settlePanelRead(key, () => json<T>(path)) as Promise<PanelReadResult<T>>;
}

export function useFactoryApi(pollMilliseconds = 5000) {
  const [connection, setConnection] = useState<ConnectionState>('connecting');
  const [snapshot, setSnapshot] = useState<CoordinatorSnapshot | null>(null);
  const [capabilities, setCapabilities] = useState<FactoryCapabilities | null>(null);
  const [authority, setAuthority] = useState<FactoryAuthority | null>(null);
  const [machineValidation, setMachineValidation] = useState<MachineValidation | null>(null);
  const [laneInventory, setLaneInventory] = useState<LaneInventory | null>(null);
  const [ecologicalValidation, setEcologicalValidation] = useState<EcologicalValidation | null>(null);
  const [noisyHashes, setNoisyHashes] = useState<NoisyHashStatus | null>(null);
  const [validationObservatory, setValidationObservatory] = useState<ValidationObservatory | null>(null);
  const [hashAnalysisBackend, setHashAnalysisBackend] = useState<HashAnalysisBackendStatus | null>(null);
  const [fidMatchingBackend, setFidMatchingBackend] = useState<FidMatchingBackendStatus | null>(null);
  const [retention, setRetention] = useState<RetentionStatus | null>(null);
  const [exportStatus, setExportStatus] = useState<ExportStatus | null>(null);
  const [events, setEvents] = useState<CoordinatorEvent[]>([]);
  const [timings, setTimings] = useState<TimingSnapshot | null>(null);
  const [preflight, setPreflight] = useState<OperationsPreflight | null>(null);
  const [timingsError, setTimingsError] = useState<string | null>(null);
  const [panelErrors, setPanelErrors] = useState<Partial<Record<PanelReadKey, string>>>({});
  const [error, setError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const hasSuccessfulRead = useRef(false);
  const refreshInFlight = useRef(false);
  const eventCursor = useRef(0);
  const eventHistory = useRef<CoordinatorEvent[]>([]);
  const selectedValidationRun = useRef<string | null>(null);
  const capabilityCache = useRef<FactoryCapabilities | null>(null);
  const authorityCache = useRef<FactoryAuthority | null>(null);
  const lastCapabilityRead = useRef(0);
  const recordPanelReads = useCallback((reads: Array<PanelReadResult<unknown>>) => {
    setPanelErrors(current => {
      const next = { ...current };
      for (const read of reads) {
        if (read.error) next[read.key] = read.error;
        else delete next[read.key];
      }
      return next;
    });
  }, []);
  const workloadActive = Boolean(
    machineValidation
    && ['queued', 'preparing-index', 'running', 'pausing', 'postprocessing', 'retaining'].includes(machineValidation.run.state),
  ) || Boolean(
    snapshot
    && (snapshot.counts.leased > 0 || snapshot.counts.running > 0),
  );
  const effectivePollMilliseconds = workloadActive
    ? pollMilliseconds
    : Math.max(pollMilliseconds, idlePollMilliseconds);

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
        const reads = await Promise.all([
          panelJson<FactoryCapabilities>('capabilities', 'capabilities'),
          panelJson<FactoryAuthority>('authority', 'authority'),
          panelJson<LaneInventory>('lane-inventory', 'lane-inventory'),
          panelJson<EcologicalValidation>('ecological-validation', 'ecological-validation'),
          panelJson<RetentionStatus>('retention', 'retention'),
          panelJson<ValidationObservatory>('validation-observatory', `validation-observatory${selectedValidationRun.current ? `?run_id=${encodeURIComponent(selectedValidationRun.current)}` : ''}`),
          panelJson<HashAnalysisBackendStatus>('hash-analysis-backend', 'hash-analysis-backend'),
          panelJson<FidMatchingBackendStatus>('fid-matching-backend', 'fid-matching-backend'),
          panelJson<NoisyHashStatus>('noisy-hashes', 'noisy-hashes'),
          panelJson<ExportStatus>('export', 'export'),
        ]);
        recordPanelReads(reads as Array<PanelReadResult<unknown>>);
        const [capabilityRead, authorityRead, laneInventoryRead, ecologicalRead, retentionRead, observatoryRead, hashBackendRead, fidBackendRead, noisyRead, exportRead] = reads;
        if (capabilityRead.value) {
          capabilityCache.current = capabilityRead.value;
          setCapabilities(capabilityRead.value);
        }
        if (authorityRead.value) {
          authorityCache.current = authorityRead.value;
          setAuthority(authorityRead.value);
          setMachineValidation(authorityRead.value.machine_validations[0] ?? null);
        }
        if (capabilityRead.value && authorityRead.value) lastCapabilityRead.current = Date.now();
        if (laneInventoryRead.value) setLaneInventory(laneInventoryRead.value);
        if (ecologicalRead.value) setEcologicalValidation(ecologicalRead.value);
        if (noisyRead.value) setNoisyHashes(noisyRead.value);
        if (retentionRead.value) setRetention(retentionRead.value);
        if (exportRead.value) setExportStatus(exportRead.value);
        if (observatoryRead.value) setValidationObservatory(observatoryRead.value);
        if (hashBackendRead.value) setHashAnalysisBackend(hashBackendRead.value);
        if (fidBackendRead.value) setFidMatchingBackend(fidBackendRead.value);
      } else {
        const reads = await Promise.all([
          panelJson<MachineValidationLive>('machine-validation/run', 'machine-validation/run'),
          panelJson<EcologicalValidation>('ecological-validation', 'ecological-validation'),
          panelJson<NoisyHashStatus>('noisy-hashes', 'noisy-hashes'),
          panelJson<RetentionStatus>('retention', 'retention'),
          panelJson<ValidationObservatory>('validation-observatory', `validation-observatory${selectedValidationRun.current ? `?run_id=${encodeURIComponent(selectedValidationRun.current)}` : ''}`),
          panelJson<HashAnalysisBackendStatus>('hash-analysis-backend', 'hash-analysis-backend'),
          panelJson<FidMatchingBackendStatus>('fid-matching-backend', 'fid-matching-backend'),
        ]);
        recordPanelReads(reads as Array<PanelReadResult<unknown>>);
        const [machineRead, ecologicalRead, noisyRead, retentionRead, observatoryRead, hashBackendRead, fidBackendRead] = reads;
        if (machineRead.value) {
          setMachineValidation(current => current ? {
            ...current,
            run: machineRead.value?.run ?? current.run,
            canary_gate: machineRead.value?.canary_gate ?? current.canary_gate,
            fid_matching: machineRead.value?.fid_matching ?? current.fid_matching,
          } : current);
        }
        if (ecologicalRead.value) setEcologicalValidation(ecologicalRead.value);
        if (noisyRead.value) setNoisyHashes(noisyRead.value);
        if (retentionRead.value) setRetention(retentionRead.value);
        if (observatoryRead.value) setValidationObservatory(observatoryRead.value);
        if (hashBackendRead.value) setHashAnalysisBackend(hashBackendRead.value);
        if (fidBackendRead.value) setFidMatchingBackend(fidBackendRead.value);
      }
      if (health.coordinator.state === 'ready') {
        const reads = await Promise.all([
          panelJson<CoordinatorSnapshot>('snapshot', 'snapshot?detail=control-panel'),
          panelJson<TimingSnapshot>('timings', 'timings?limit=200'),
          panelJson<OperationsPreflight>('preflight', 'preflight'),
        ]);
        recordPanelReads(reads as Array<PanelReadResult<unknown>>);
        const [snapshotRead, timingRead, preflightRead] = reads;
        if (snapshotRead.value) setSnapshot(snapshotRead.value);
        if (preflightRead.value) setPreflight(preflightRead.value);
        if (timingRead.value) setTimings(timingRead.value);
        setTimingsError(timingRead.error);
        if (snapshotRead.value) {
          const eventRead = await settlePanelRead(
            'events',
            async () => {
              await refreshEvents(snapshotRead.value as CoordinatorSnapshot);
              return true;
            },
          ) as PanelReadResult<boolean>;
          recordPanelReads([eventRead]);
        }
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
  }, [recordPanelReads, refreshEvents, resetEvents]);

  useEffect(() => {
    const kickoff = window.setTimeout(() => void refresh(false), 0);
    const timer = window.setInterval(() => void refresh(false), effectivePollMilliseconds);
    return () => {
      window.clearTimeout(kickoff);
      window.clearInterval(timer);
    };
  }, [effectivePollMilliseconds, refresh]);

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

  const refreshValidation = useCallback(async () => {
    const [machineResult, ecologicalResult, noisyResult, observatoryResult] = await Promise.all([
      json<MachineValidation>('machine-validation'),
      json<EcologicalValidation>('ecological-validation'),
      json<NoisyHashStatus>('noisy-hashes'),
      json<ValidationObservatory>(`validation-observatory${selectedValidationRun.current ? `?run_id=${encodeURIComponent(selectedValidationRun.current)}` : ''}`),
    ]);
    setMachineValidation(machineResult);
    setEcologicalValidation(ecologicalResult);
    setNoisyHashes(noisyResult);
    setValidationObservatory(observatoryResult);
    setError(null);
  }, []);

  const selectValidationRun = useCallback(async (runKey: string) => {
    try {
      const result = await json<ValidationObservatory>(
        `validation-observatory?run_id=${encodeURIComponent(runKey)}`,
      );
      selectedValidationRun.current = runKey;
      setValidationObservatory(result);
      setError(null);
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Validation run unavailable';
      setError(message);
      throw caught;
    }
  }, []);

  const runMachineValidation = useCallback(async (mode: 'canary' | 'full', runId?: string) => {
    setBusyAction(`machine-validation-${mode}`);
    try {
      await json<MachineValidationRun>('machine-validation/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, ...(runId ? { run_id: runId } : {}) }),
      });
      await refreshValidation();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Machine validation failed to start';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, [refreshValidation]);

  const controlMachineValidation = useCallback(async (action: 'pause' | 'resume') => {
    setBusyAction(`machine-validation-${action}`);
    try {
      await json<MachineValidationRun>(`machine-validation/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      await refreshValidation();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : `Machine validation failed to ${action}`;
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, [refreshValidation]);

  const importEcological = useCallback(async (
    file: File,
    metadata: {
      label: string;
      platformHint: string;
      expectedPresent: string[];
      expectedAbsent: string[];
      truthComplete: boolean;
    },
  ) => {
    setBusyAction('ecological-import');
    try {
      const response = await fetch('/api/fidb/ecological-validation/import', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-FIDB-Filename': encodeURIComponent(file.name),
          'X-FIDB-Label': encodeURIComponent(metadata.label),
          'X-FIDB-Platform-Hint': metadata.platformHint,
          'X-FIDB-Expected-Present': encodeURIComponent(metadata.expectedPresent.join(',')),
          'X-FIDB-Expected-Absent': encodeURIComponent(metadata.expectedAbsent.join(',')),
          'X-FIDB-Truth-Complete': String(metadata.truthComplete),
        },
        body: file,
      });
      const document = await response.json() as ApiErrorBody;
      if (!response.ok) {
        throw new Error(document.error?.message ?? `Ecological import failed (${response.status})`);
      }
      await refreshValidation();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Ecological import failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, [refreshValidation]);

  const runEcological = useCallback(async (caseId: string) => {
    setBusyAction(`ecological-run:${caseId}`);
    try {
      await json<EcologicalCase>('ecological-validation/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId }),
      });
      await refreshValidation();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Ecological check failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, [refreshValidation]);

  const decideNoisyHash = useCallback(async (
    signatureId: string,
    state: NoisyHashRow['disposition'],
    reason: string,
  ) => {
    setBusyAction(`noisy-hash:${signatureId}`);
    try {
      const result = await json<NoisyHashStatus>('noisy-hashes/decision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ signature_id: signatureId, state, reason }),
      });
      setNoisyHashes(result);
      setError(null);
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Noisy-hash decision failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, []);

  const runRetention = useCallback(async (
    action: 'plan' | 'apply',
    planDigest?: string,
  ) => {
    setBusyAction(`retention-${action}`);
    try {
      const result = await json<RetentionStatus>(`retention/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(action === 'apply' ? { plan_digest: planDigest } : {}),
      });
      setRetention(result);
      setError(null);
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Retention action failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, []);

  const runExport = useCallback(async (action: 'preview' | 'safeguard' | 'build') => {
    setBusyAction(`export-${action}`);
    try {
      const result = await json<ExportStatus>(`export/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      setExportStatus(result);
      setError(null);
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : `Export ${action} failed`;
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, []);

  const setHashAnalysisMode = useCallback(async (mode: 'auto' | 'cpu' | 'gpu') => {
    setBusyAction('hash-analysis-mode');
    try {
      const result = await json<HashAnalysisBackendStatus>('hash-analysis-backend/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      });
      setHashAnalysisBackend(result);
      setError(null);
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'Hash backend setting failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, []);

  const setFidMatchingMode = useCallback(async (mode: 'auto' | 'cpu' | 'gpu') => {
    setBusyAction('fid-matching-mode');
    try {
      const result = await json<FidMatchingBackendStatus>('fid-matching-backend/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      });
      setFidMatchingBackend(result);
      setError(null);
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : 'FID matching backend setting failed';
      setError(message);
      throw caught;
    } finally {
      setBusyAction(null);
    }
  }, []);

  return {
    connection,
    snapshot,
    capabilities,
    authority,
    machineValidation,
    laneInventory,
    ecologicalValidation,
    noisyHashes,
    validationObservatory,
    hashAnalysisBackend,
    fidMatchingBackend,
    retention,
    exportStatus,
    events,
    timings,
    preflight,
    timingsError,
    panelErrors,
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
    importEcological,
    runEcological,
    runMachineValidation,
    selectValidationRun,
    setHashAnalysisMode,
    setFidMatchingMode,
    pauseMachineValidation: () => controlMachineValidation('pause'),
    resumeMachineValidation: () => controlMachineValidation('resume'),
    decideNoisyHash,
    planRetention: () => runRetention('plan'),
    applyRetention: (planDigest: string) => runRetention('apply', planDigest),
    previewExport: () => runExport('preview'),
    safeguardExport: () => runExport('safeguard'),
    buildExport: () => runExport('build'),
  };
}
