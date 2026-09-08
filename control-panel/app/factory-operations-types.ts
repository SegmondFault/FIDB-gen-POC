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


