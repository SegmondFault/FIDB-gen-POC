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


