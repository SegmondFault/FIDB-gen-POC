'use client';

import { Fragment, useState, type CSSProperties, type Dispatch, type SetStateAction } from 'react';
import {
  type CampaignProgramme,
  type CohortValidationLifecycle,
  type CohortValidationProgramme,
  type CoverageLanguage,
  type FactoryCapabilities,
  type PlanDraftResult,
  type WidthAxisId,
  type WidthCompilation,
  type WidthStudy,
} from './use-factory-api';
import {
  etaDuration,
  formatBytes,
  formatDurationNs,
  formatPlanningDurationNs,
} from './formatters';
import { ViewIntro, type FactoryApiState } from './panel-primitives';
import type { BatchRow } from './view-models';

export function LanguageScopeSelector({ languages, selectedId, onSelect }: { languages: CoverageLanguage[]; selectedId: string; onSelect: (id: string) => void }) {
  const activeLanguages = languages.filter(language => language.state === 'active-scope');
  return <section className="language-scope-selector" aria-label="Active library language scope"><div><span>ACTIVE LIBRARY MATRIX</span><strong>C-family scope · C++ only where a C library requires it</strong></div><div>{activeLanguages.map(language => <button key={language.id} className={selectedId === language.id ? 'active' : ''} onClick={() => onSelect(language.id)} aria-pressed={selectedId === language.id}><b>{language.label}</b><small>{language.state.replaceAll('-', ' ')}</small></button>)}</div></section>;
}

function WidthStudyPanel({ study, compilation, capabilities }: { study: WidthStudy; compilation?: WidthCompilation; capabilities: FactoryCapabilities | null }) {
  const defaultPreset = study.presets.find(preset => preset.id === study.default_preset) ?? study.presets[0];
  const [axisValues, setAxisValues] = useState<Record<WidthAxisId, number>>(() => Object.fromEntries(
    study.axes.map(axis => [axis.id, defaultPreset?.[axis.id] ?? axis.default]),
  ) as Record<WidthAxisId, number>);
  const [targetFamilies, setTargetFamilies] = useState(study.scaling.default_target_families);
  const [workers, setWorkers] = useState(study.scaling.default_workers);
  const [complexityMultiplier, setComplexityMultiplier] = useState(1);
  const [retainedMultiplier, setRetainedMultiplier] = useState(1);
  const buildWidth = axisValues.releases * axisValues.routes * axisValues.build_profiles * axisValues.artifact_shapes;
  const activePreset = study.presets.find(preset => study.axes.every(axis => preset[axis.id] === axisValues[axis.id]));
  const activeRequirements = study.toolchain_requirements.slice(0, axisValues.routes);
  const capabilityById = new Map((capabilities?.toolchains.entries ?? []).map(row => [row.id, row]));
  const requirementState = (requirement: WidthStudy['toolchain_requirements'][number]) => {
    if (requirement.route_state === 'pinned-source' && requirement.source_capable_toolchain_ids.some(id => capabilityById.get(id)?.state === 'verified-cached')) return 'pinned-cache-ready';
    return requirement.route_state;
  };
  const stateLabel: Record<string, string> = {
    installed: 'HOST INSTALLED',
    'pinned-cache-ready': 'PINNED CACHE READY',
    'pinned-source': 'PINNED SOURCE',
    'archive-only': 'ARCHIVE EVIDENCE ONLY',
    'remote-required': 'REMOTE WORKER REQUIRED',
    'definition-required': 'DEFINITION + PIN REQUIRED',
  };
  const nextGate: Record<string, string> = {
    installed: 'Verified',
    'pinned-cache-ready': 'Qualify route',
    'pinned-source': 'Fetch + qualify',
    'archive-only': 'Add compiler pin',
    'remote-required': 'Enroll worker',
    'definition-required': 'Define + pin',
  };
  const stateCounts = activeRequirements.reduce<Record<string, number>>((counts, requirement) => {
    const state = requirementState(requirement);
    counts[state] = (counts[state] ?? 0) + 1;
    return counts;
  }, {});
  const projectionFor = (families: number) => {
    const buildCells = families * buildWidth;
    const analyses = buildCells * axisValues.analysis_profiles;
    const executions = analyses * axisValues.replay;
    const retainedBytes = executions * study.calibration.retained_bundle_bytes_p50 * retainedMultiplier;
    const compactBytes = analyses * study.calibration.compact_output_bytes_p50 * retainedMultiplier;
    return {
      families,
      buildCells,
      analyses,
      executions,
      policyEvaluations: analyses * axisValues.admission_profiles,
      idealWallNs: executions * study.calibration.successful_wall_ns_p50 * complexityMultiplier / workers,
      retainedBytes,
      compactBytes,
      diskBytes: retainedBytes + compactBytes,
    };
  };
  const projections = study.scaling.comparison_family_counts.map(projectionFor);
  const baseline = projectionFor(study.family_count);
  const target = projectionFor(targetFamilies);
  const selectPreset = (preset: WidthStudy['presets'][number]) => setAxisValues(Object.fromEntries(
    study.axes.map(axis => [axis.id, preset[axis.id]]),
  ) as Record<WidthAxisId, number>);
  const updateAxis = (axis: WidthAxisId, value: number) => setAxisValues(current => ({ ...current, [axis]: value }));
  const applicability = new Map(compilation?.applicability.map(row => [`${row.route_id}:${row.profile_id}`, row]));
  return <section className="panel width-study-panel">
    <div className="panel-header width-study-header"><h3>Width laboratory · {study.id}</h3><div><span className="plan-state">DEFINED · DISARMED</span><code>{study.authority_path}</code></div></div>
    <div className="width-study-warning"><span>!</span><p><strong>This is coverage intent, not queued work.</strong><small>{study.queue_policy}</small></p></div>
    {compilation && <section className="compiled-width">
      <header><h4>Applicability · {compilation.id} · {compilation.fixed_recipe}</h4><code>{compilation.compilation_digest.slice(0, 16)}…</code></header>
      {compilation.freeze && <div className="compiled-width-freeze"><span>✓</span><p><strong>FROZEN MEASURED WIDTH · {compilation.freeze.completed_executions} EXECUTIONS COMPLETE</strong><small>{formatPlanningDurationNs(compilation.freeze.wall_time_ns)} wall · {formatBytes(compilation.freeze.peak_active_replay_scratch_bytes)} peak scratch · {formatBytes(compilation.freeze.retained_bytes)} retained · {compilation.freeze.artifact_byte_identical_cells}/54 artifact-byte repeatable · {compilation.freeze.fid_semantic_identical_cells}/54 FID-semantic repeatable</small></p><code>{compilation.freeze.evidence_path}</code></div>}
      <div className="compiled-width-metrics"><article><span>DECLARED ROUTES</span><strong>{compilation.summary.declared_route_slots}</strong><small>{compilation.summary.qualified_routes} qualified now</small></article><article><span>PROFILE SLOTS</span><strong>{compilation.summary.declared_build_profile_slots}</strong><small>{compilation.summary.catalogued_build_profiles} named</small></article><article><span>FEASIBLE BUILD CELLS</span><strong>{compilation.summary.feasible_build_cells}</strong><small>{compilation.summary.executable_route_profile_pairs} applicable pairs</small></article><article><span>REPLAYED FULL PATHS</span><strong>{compilation.summary.feasible_full_path_executions}</strong><small>×{compilation.summary.selected_replay} independent attempts</small></article><article><span>VARIABLES VISIBLE</span><strong>{compilation.summary.sensitivity_factors}</strong><small>{compilation.summary.factors_with_variants} have named choices</small></article></div>
      <details className="applicability-map" open><summary>Target × exact compiler × treatment applicability <span>{compilation.routes.length} routes · {new Set(compilation.routes.map(route => route.compiler_id)).size} compiler identities · {compilation.summary.executable_route_profile_pairs} executable</span></summary><div className="applicability-scroll"><div className="applicability-grid" style={{ '--width-cols': compilation.build_profiles.length } as CSSProperties}><div className="corner">TARGET / COMPILER</div>{compilation.build_profiles.map(profile => <div className="profile-head" key={profile.id} title={profile.controls.join(' · ')}><b>{profile.label}</b><small>{profile.execution_treatment ?? 'not wired'}</small></div>)}{compilation.routes.map(route => <Fragment key={route.id}><div className="route-head"><b>{route.label}</b><small>{route.target_id} · {route.compiler_id}</small></div>{compilation.build_profiles.map(profile => { const cell = applicability.get(`${route.id}:${profile.id}`); return <div key={`${route.id}:${profile.id}`} className={`applicability-cell ${cell?.state ?? 'unavailable'}`} title={cell?.reasons.join(' · ') || cell?.treatment_id || 'Executable'}>{cell?.state === 'executable' ? '●' : cell?.state === 'inapplicable' ? '—' : '!'}</div>; })}</Fragment>)}</div></div></details>
      <div className="compiled-layer-grid"><section><span>ARTIFACT SHAPES · {compilation.artifact_profiles.length}</span>{compilation.artifact_profiles.map(row => <article key={row.id}><b>{row.label}</b><em className={row.state}>{row.state}</em><small>{row.description}</small></article>)}</section><section><span>ANALYSIS PROFILES · {compilation.analysis_profiles.length}</span>{compilation.analysis_profiles.map(row => <article key={row.id}><b>{row.label}</b><em className={row.state}>{row.state}</em><small>{row.description}</small></article>)}</section><section><span>ADMISSION PROFILES · {compilation.admission_profiles.length}</span>{compilation.admission_profiles.map(row => <article key={row.id}><b>{row.label}</b><em className={row.state}>{row.state}</em><small>{row.description}</small></article>)}</section></div>
      <details className="compiled-factor-ledger"><summary>All {compilation.factors.length} studied variables <span>registered, desired, guarded and unresolved choices remain visible</span></summary><div>{compilation.factors.map((factor, index) => <article key={factor.id}><b>{String(index + 1).padStart(2, '0')}</b><p><strong>{factor.label}</strong><small>{factor.id} · {factor.stage}</small></p><span>{factor.variants.length ? factor.variants.map(row => `${row.label} [${row.state}]`).join(' · ') : 'No named variants yet · explicit unresolved width'}</span></article>)}</div></details>
    </section>}
    <div className="width-study-presets"><span>WIDTH PRESET</span><div>{study.presets.map(preset => <button key={preset.id} className={activePreset?.id === preset.id ? 'active' : ''} onClick={() => selectPreset(preset)} title={preset.description}><b>{preset.label}</b><small>{preset.metrics.build_width_per_family.toLocaleString()} builds/family · {preset.evidence_class}</small></button>)}</div><em>{activePreset ? activePreset.description : 'Custom width · bounded by the declared study authority'}</em></div>
    <div className="width-axis-grid">{study.axes.map(axis => <label key={axis.id}><span><b>{axis.label}</b><strong>{axisValues[axis.id]}</strong></span><input type="range" min={axis.minimum} max={axis.maximum} value={axisValues[axis.id]} onChange={event => updateAxis(axis.id, Number(event.target.value))} /><small>{axis.minimum}–{axis.maximum} {axis.unit} · {axis.layer}</small><p>{axis.description}</p></label>)}</div>
    <div className="width-study-metrics">
      <article><span>BUILD WIDTH / FAMILY</span><strong>{buildWidth.toLocaleString()}</strong><small>releases × routes × build profiles × shapes</small></article>
      <article><span>TOP-10 BUILD CELLS</span><strong>{baseline.buildCells.toLocaleString()}</strong><small>distinct compiled/artifact identities</small></article>
      <article><span>ANALYSIS RUNS</span><strong>{baseline.analyses.toLocaleString()}</strong><small>reuse build artifacts · ×{axisValues.analysis_profiles}</small></article>
      <article><span>FULL-PATH EXECUTIONS</span><strong>{baseline.executions.toLocaleString()}</strong><small>analysis runs × {axisValues.replay} replay</small></article>
      <article><span>POLICY EVALUATIONS</span><strong>{baseline.policyEvaluations.toLocaleString()}</strong><small>reuse evidence · ×{axisValues.admission_profiles}</small></article>
    </div>
    <div className="width-study-body">
      <section className="width-family-card"><header><h4>Subject set · top 10 C</h4><span>{study.readiness.reviewed_recipe_families}/{study.family_count} recipe-ready</span></header><div>{study.families.map(family => <article key={family.id}><b>{String(family.rank).padStart(2, '0')}</b><p><strong>{family.label}</strong><small>{family.selection_evidence}</small></p><em className={family.recipe_state}>{family.recipe_state.replaceAll('-', ' ')}</em></article>)}</div><footer>{study.caveat}</footer></section>
      <section className="width-scale-card"><header><h4>10 → 80 capacity</h4><span>n={study.calibration.sample_count} smoke samples</span></header>
        <div className="width-scale-controls"><label><span>FAMILIES</span><div>{study.scaling.comparison_family_counts.map(count => <button key={count} className={targetFamilies === count ? 'active' : ''} onClick={() => setTargetFamilies(count)}>{count}</button>)}</div></label><label><span>WORKER SLOTS <b>{workers}</b></span><input type="range" min="1" max={study.scaling.maximum_workers} value={workers} onChange={event => setWorkers(Number(event.target.value))} /></label><label><span>TIME COMPLEXITY × <b>{complexityMultiplier}</b></span><input type="range" min="1" max="50" value={complexityMultiplier} onChange={event => setComplexityMultiplier(Number(event.target.value))} /></label><label><span>RETAINED BYTES × <b>{retainedMultiplier}</b></span><input type="range" min="1" max="20" value={retainedMultiplier} onChange={event => setRetainedMultiplier(Number(event.target.value))} /></label></div>
        <div className="width-delta"><span>10 → {targetFamilies} DELTA</span><div><p><strong>+{(target.executions - baseline.executions).toLocaleString()}</strong><small>full-path executions</small></p><p><strong>+{formatPlanningDurationNs(target.idealWallNs - baseline.idealWallNs)}</strong><small>ideal occupied-slot wall time</small></p><p><strong>+{formatBytes(target.diskBytes - baseline.diskBytes)}</strong><small>retained + compact disk proxy</small></p><p><strong>{formatBytes(workers * study.calibration.peak_worker_rss_bytes_p50)}</strong><small>concurrent RSS proxy</small></p></div></div>
        <div className="width-scale-table"><div className="head"><span>Families</span><span>Build cells</span><span>Executions</span><span>Ideal wall</span><span>Retained</span><span>Compact</span></div>{projections.map(row => <div className={row.families === targetFamilies ? 'selected' : ''} key={row.families}><strong>{row.families}</strong><span>{row.buildCells.toLocaleString()}</span><span>{row.executions.toLocaleString()}</span><b>{formatPlanningDurationNs(row.idealWallNs)}</b><span>{formatBytes(row.retainedBytes)}</span><span>{formatBytes(row.compactBytes)}</span></div>)}</div>
        <footer><strong>Smoke-linear projection; not an ETA.</strong> {study.calibration.caveat} Scratch peak: {study.calibration.scratch_peak_state}. Model: {study.scaling.model}.</footer>
      </section>
    </div>
    <section className="width-toolchain-card"><header><h4>Route acquisition · {axisValues.routes}/{study.toolchain_requirements.length} active</h4><div className="width-route-counts"><span className="installed">{(stateCounts.installed ?? 0) + (stateCounts['pinned-cache-ready'] ?? 0)} ready</span><span className="remote-required">{stateCounts['remote-required'] ?? 0} remote</span><span className="definition-required">{(stateCounts['definition-required'] ?? 0) + (stateCounts['archive-only'] ?? 0)} definitions</span></div></header><div className="width-toolchain-list">{study.toolchain_requirements.map(requirement => {
      const active = requirement.order <= axisValues.routes;
      const state = requirementState(requirement);
      return <article className={active ? `active ${state}` : 'future'} key={requirement.id}><b>{String(requirement.order).padStart(2, '0')}</b><div><strong>{requirement.target_label}</strong><small>{requirement.target_id} · {requirement.wave}</small></div><p><strong>{requirement.compiler_label}</strong><small>{requirement.worker_class} · {requirement.acquisition}</small></p><span className={`route-requirement-state ${state}`}>{active ? stateLabel[state] : 'OUTSIDE CURRENT WIDTH'}</span><code>{requirement.version_policy}</code><button disabled title="Install actions require an exact reviewed pin and remain intentionally disabled in this coverage-intent batch">{active ? nextGate[state] : 'Later wave'}</button></article>;
    })}</div></section>
    {study.readiness.blockers.length > 0 && <details className="width-blockers"><summary>Materialization blockers <span>{study.readiness.blockers.length}</span></summary><div>{study.readiness.blockers.map(blocker => <p key={blocker}>! {blocker}</p>)}</div></details>}
  </section>;
}

type RecipeMode = 'native' | 'source' | 'malware' | 'catalog';
type RecipeReadiness = 'source' | 'archive' | 'unmet' | 'artifact';
type RecipeOption = {
  id: string;
  name: string;
  version: string;
  mode: RecipeMode;
  matchSet: string;
  familyGroup: string;
  detail: string;
  coverage: string;
  readiness: RecipeReadiness;
  batch: string;
  planEligible: boolean;
  authority: string;
  recipePath?: string;
  adapter?: string;
  url?: string;
  sha256?: string;
  gap?: string;
  toolchainFamily?: string;
  toolchainVariants?: string[];
};

export function MatrixView({ batchOrder, rows, factory, selectedLanguageId, setSelectedLanguageId }: { batchOrder: string[]; rows: BatchRow[]; factory: FactoryApiState; selectedLanguageId: string; setSelectedLanguageId: Dispatch<SetStateAction<string>> }) {
  const executor = 'local';
  const timing = factory.timings;
  const [selectedRecipesOverride, setSelectedRecipesOverride] = useState<string[] | null>(null);
  const [routeSelectionsOverride, setRouteSelectionsOverride] = useState<Record<string, string[]> | null>(null);
  const [factorSelectionsOverride, setFactorSelectionsOverride] = useState<Record<string, string[]> | null>(null);
  const [collapsedVariableGroups, setCollapsedVariableGroups] = useState(['executable-routes', 'analysis-controls', 'environment-identity', 'fid-matching', 'truth-admission', 'hardening-instrumentation', 'link-output', 'analysis-recovery']);
  const [collapsedLibraryGroups, setCollapsedLibraryGroups] = useState<string[]>([]);
  const [matrixLayer, setMatrixLayer] = useState<'both' | 'plan' | 'inventory'>('both');
  const [queueStrategyOverride, setQueueStrategyOverride] = useState<string | null>(null);
  const [queueMessage, setQueueMessage] = useState('');
  const [inspectedRecipe, setInspectedRecipe] = useState<string | null>(null);
  const [inspectedFactor, setInspectedFactor] = useState<string | null>(null);
  const [tomlOpen, setTomlOpen] = useState(true);
  const [scopeOpen, setScopeOpen] = useState(false);
  const [widthLaboratoryOpen, setWidthLaboratoryOpen] = useState(false);
  const [crosspointOpen, setCrosspointOpen] = useState(false);
  const [draftName, setDraftName] = useState('matrix-draft');
  const [draftResult, setDraftResult] = useState<PlanDraftResult | null>(null);
  const [validatedToml, setValidatedToml] = useState<string | null>(null);
  const [savedDraftSha256, setSavedDraftSha256] = useState<string | null>(null);
  const [draftMessage, setDraftMessage] = useState('Resolve the generated request before saving it.');
  const authority = factory.authority;
  const coverageUniverse = authority?.coverage_universe;
  const widthStudy = authority?.width_studies.find(study => study.language_id === selectedLanguageId);
  const widthCompilation = authority?.width_compilations
    .filter(compilation => compilation.language_id === selectedLanguageId)
    .sort((left, right) => (
      right.summary.feasible_full_path_executions
      - left.summary.feasible_full_path_executions
    ))[0];
  const machineValidation = selectedLanguageId === 'c'
    ? factory.machineValidation
    : authority?.machine_validations.find(validation => validation.language_id === selectedLanguageId);
  const ecologicalValidation = factory.ecologicalValidation;
  const noisyHashes = factory.noisyHashes;
  const hashDiscrimination = authority?.hash_discrimination;
  const retention = factory.retention;
  const qualificationPipeline = authority?.qualification_pipeline;
  const selectedLanguage = coverageUniverse?.languages.find(language => language.id === selectedLanguageId);
  const languageProfiles = (coverageUniverse?.profiles ?? []).filter(profile => profile.language_id === selectedLanguageId);
  const inventoryCells = authority?.plans.flatMap(plan => (
    Object.entries(plan.inventory.cells)
  )) ?? [];
  const builtCellIds = new Set(
    inventoryCells
      .filter(([, inventory]) => inventory.state === 'built')
      .map(([cellId]) => cellId),
  );
  const artifactOnlyCellIds = new Set(
    inventoryCells
      .filter(([, inventory]) => inventory.state === 'artifact-only')
      .map(([cellId]) => cellId),
  );
  const cellMatchesRecipe = (cellId: string, name: string, version: string) => (
    cellId.includes(':' + name + '-' + version + ':')
    || cellId.includes(':' + name + '@' + version + ':')
  );
  const authorityPlanForBatch = (batchId: string) => {
    const livePath = factory.snapshot?.batches.find(batch => batch.id === batchId)?.plan_path;
    const configuredName = rows.find(row => row.id === batchId)?.name;
    return authority?.plans.find(plan => (
      (livePath && plan.path === livePath)
      || (!livePath && configuredName && plan.name === configuredName)
    ));
  };
  const batchForRecipe = (recipeId: string) => {
    for (const batchId of batchOrder) {
      const plan = authorityPlanForBatch(batchId);
      const selected = plan?.matrices.some(matrix => (
        Array.isArray(matrix.recipes) && matrix.recipes.includes(recipeId)
      ));
      if (selected) return batchId;
    }
    return 'unassigned';
  };
  const recipeOptions: RecipeOption[] = (authority?.recipes ?? []).map(recipe => {
    const mode: RecipeMode = recipe.kind === 'native'
      ? 'native'
      : recipe.kind === 'malware'
        ? 'malware'
        : 'source';
    const matchingToolchains = (authority?.toolchains ?? []).filter(toolchain => (
      toolchain.family === recipe.toolchain_family
      && (!recipe.toolchain_variants?.length
        || recipe.toolchain_variants.includes(toolchain.variant))
    ));
    const sealedCount = [...builtCellIds].filter(cellId => (
      cellMatchesRecipe(cellId, recipe.name, recipe.version)
    )).length;
    const artifactOnlyCount = [...artifactOnlyCellIds].filter(cellId => (
      cellMatchesRecipe(cellId, recipe.name, recipe.version)
    )).length;
    const sourceReady = mode === 'native'
      || matchingToolchains.some(toolchain => toolchain.source_capable);
    const archiveCount = matchingToolchains.filter(toolchain => (
      toolchain.archive_capable
    )).length;
    const readiness: RecipeReadiness = sealedCount > 0
      ? 'artifact'
      : sourceReady
        ? 'source'
        : archiveCount > 0
          ? 'archive'
          : 'unmet';
    const coverage = sealedCount > 0
      ? sealedCount + ' sealed build' + (sealedCount === 1 ? '' : 's')
      : artifactOnlyCount > 0
        ? artifactOnlyCount + ' unsealed artifact' + (artifactOnlyCount === 1 ? '' : 's')
        : archiveCount > 0 && !sourceReady
          ? archiveCount + ' archive pin' + (archiveCount === 1 ? '' : 's')
          : 'not built';
    const familyGroup = recipe.kind === 'native'
      ? 'Native support libraries'
      : recipe.kind === 'malware'
        ? 'Ground-truth workloads'
        : (recipe.toolchain_family ?? 'Cross-built libraries') + ' runtime family';
    return {
      id: recipe.name,
      name: recipe.name,
      version: recipe.version,
      mode,
      matchSet: recipe.kind === 'malware'
        ? 'Ground-truth match set'
        : 'Reviewed reference match set',
      familyGroup,
      detail: recipe.build_adapter + ' · ' + (recipe.static_archives?.join(', ') ?? recipe.library_path ?? 'reviewed output'),
      coverage,
      readiness,
      batch: batchForRecipe(recipe.id),
      planEligible: recipe.kind !== 'malware' && sourceReady,
      authority: recipe.authority_path,
      recipePath: recipe.authority_path,
      adapter: recipe.build_adapter,
      url: recipe.url,
      sha256: recipe.sha256,
      gap: sourceReady
        ? undefined
        : 'No reviewed executable source route is registered for this recipe.',
      toolchainFamily: recipe.toolchain_family,
      toolchainVariants: recipe.toolchain_variants,
    };
  });
  const toolchainOptions = (authority?.toolchains ?? []).map(toolchain => ({
    id: toolchain.id,
    title: toolchain.machine + ' · ' + toolchain.variant,
    compiler: toolchain.source_capable
      ? 'Pinned cross compiler · ' + toolchain.version
      : 'Pinned archive extraction · ' + toolchain.version,
    abi: String(toolchain.elf_class) + '-bit · ' + toolchain.endianness,
    language: toolchain.machine + ':' + toolchain.endianness + ':' + String(toolchain.elf_class),
    state: toolchain.source_capable ? 'source' : 'archive',
    ref: toolchain.id,
    variant: toolchain.variant,
    family: toolchain.family,
    sourceCapable: toolchain.source_capable,
    archiveCapable: toolchain.archive_capable,
  }));
  const factorById = new Map(
    (authority?.factors ?? []).map(factor => [factor.id, factor]),
  );
  const humanize = (value: string) => value
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
  const variantGroupIds = Array.from(new Set(
    (authority?.factor_variants ?? []).map(variant => variant.group),
  ));
  const factorGroups = variantGroupIds.map(groupId => ({
    id: groupId,
    label: humanize(groupId),
    note: 'named variants from sensitivity/variants.toml',
    options: (authority?.factor_variants ?? [])
      .filter(variant => variant.group === groupId)
      .map(variant => ({
        id: variant.id,
        factor: variant.factor,
        label: variant.label,
        detail: factorById.get(variant.factor)?.control ?? variant.authority,
        state: variant.state,
      })),
  }));
  const factorStageIds = Array.from(new Set(
    (authority?.factors ?? []).map(factor => factor.stage),
  ));
  const catalogFactorGroups = selectedLanguageId === 'c'
    ? factorStageIds.map(stage => ({
      id: 'known-' + stage,
      label: humanize(stage),
      note: 'known C sensitivity and provenance dimensions',
      options: (authority?.factors ?? [])
        .filter(factor => factor.stage === stage)
        .map(factor => ({
          id: factor.id,
          label: factor.label,
          detail: factor.impact,
          state: factor.confidence === 'observed-sensitive' ? 'recorded' : 'known',
        })),
    }))
    : selectedLanguage
      ? [{
        id: `${selectedLanguage.id}-treatments`,
        label: `${selectedLanguage.label} treatment policy`,
        note: 'language-owned axes; finite profiles still require qualification',
        options: selectedLanguage.treatment_axes.map((axis, index) => ({
          id: `${selectedLanguage.id}:axis:${index + 1}`,
          label: axis,
          detail: selectedLanguage.denominator,
          state: selectedLanguage.state === 'vocabulary-only' ? 'conceptual' : 'known',
        })),
      }]
      : [];
  const scopedFactorGroups = selectedLanguageId === 'c' ? factorGroups : [];
  const allFactorOptions = scopedFactorGroups.flatMap(group => group.options);
  const knownFactorCount = authority?.factors.length ?? 0;
  const measuredFactorCount = authority?.factors.filter(factor => (
    factor.confidence.startsWith('observed')
  )).length ?? 0;
  const variantCountsByFactor = (authority?.factor_variants ?? []).reduce<Record<string, number>>((counts, variant) => ({
    ...counts,
    [variant.factor]: (counts[variant.factor] ?? 0) + 1,
  }), {});
  const rawNamedTreatmentSpace = selectedLanguageId === 'c' ? Object.values(variantCountsByFactor).reduce(
    (product, count) => product * count,
    Object.keys(variantCountsByFactor).length ? 1 : 0,
  ) : 0;
  const executableTargetCount = (authority?.targets ?? []).filter(target => (
    target.native_route_ids.length > 0 || target.source_capable_toolchain_ids.length > 0
  )).length;
  const targetContextOptions = (authority?.targets ?? []).map(target => {
    const executable = target.native_route_ids.length > 0 || target.source_capable_toolchain_ids.length > 0;
    const state = executable
      ? 'executable'
      : target.catalog_state === 'coverage-intent'
        ? 'conceptual'
        : target.catalog_state === 'study-observed'
          ? 'observed'
          : 'catalogued';
    return {
      id: `target:${target.id}`,
      label: target.label,
      detail: `${target.bits}-bit · ${target.endianness} · ${target.binary_format}`,
      state,
      compatible: ['native', 'source', 'malware'],
      kind: 'target',
    };
  });
  const compilerProfileOptions = languageProfiles.map(profile => ({
    id: `profile:${profile.id}`,
    label: profile.label,
    detail: `${profile.route_scope} · ${profile.controls.join(' · ')}`,
    state: profile.state,
    compatible: ['native', 'source', 'malware'],
    kind: 'profile',
  }));
  const nativeRouteOptions = (authority?.native.routes ?? []).map(route => {
    const compiler = Array.isArray(route.compiler)
      ? route.compiler.join(' ')
      : String(route.compiler ?? 'reviewed compiler');
    const targetOs = String(route.target_os ?? 'unknown');
    const architecture = String(route.architecture ?? 'unknown');
    const binaryFormat = String(route.binary_format ?? 'unknown');
    return {
      id: route.id,
      label: `${targetOs} · ${architecture}`,
      detail: `${compiler} · ${binaryFormat}`,
      state: 'registered',
      compatible: ['native'],
      kind: 'route',
      target: `${targetOs} ${architecture} ${binaryFormat}`,
      compiler,
      analysis: `${String(route.ghidra_language ?? 'route mapped')} / ${String(route.ghidra_compiler_spec ?? 'default')}`,
    };
  });
  const routeColumns = [
    ...nativeRouteOptions,
    ...toolchainOptions.map(toolchain => ({
      ...toolchain,
      label: toolchain.title,
      detail: `${toolchain.compiler} · ${toolchain.abi}`,
      compatible: ['source', 'malware'],
      kind: 'route',
      target: toolchain.abi,
      analysis: toolchain.language,
    })),
  ];
  const matrixVariableGroups = [
    { id: 'target-contexts', label: 'Target / ISA / ABI', note: 'catalogued possibility space; readiness is an overlay', options: targetContextOptions },
    { id: 'executable-routes', label: 'Executable route identities', note: 'registered native and pinned source/archive routes', options: routeColumns },
    { id: 'compiler-profiles', label: 'Compiler calibration profiles', note: 'bounded family × version × setting pack', options: compilerProfileOptions },
    ...catalogFactorGroups.map(group => ({ ...group, options: group.options.map(option => ({ ...option, kind: 'catalog', compatible: ['native', 'source', 'malware'] })) })),
    ...scopedFactorGroups.map(group => ({ ...group, options: group.options.map(option => ({ ...option, kind: 'factor', compatible: ['native'] })) })),
  ];
  const authorityDefaults = (() => {
    const recipes = new Set<string>();
    const routes: Record<string, string[]> = {};
    const factors: Record<string, string[]> = {};
    let strategy: string | undefined;
    if (!authority) return { recipes: [] as string[], routes, factors, strategy };
    for (const batchId of batchOrder) {
      const plan = authorityPlanForBatch(batchId);
      if (!plan) continue;
      strategy ||= plan.queue.strategy;
      const liveBatch = factory.snapshot?.batches.find(batch => batch.id === batchId);
      const matrices = liveBatch?.matrices
        ? plan.matrices.filter(matrix => liveBatch.matrices?.includes(String(matrix.id)))
        : plan.matrices;
      for (const matrix of matrices) {
        const recipeRefs = Array.isArray(matrix.recipes)
          ? matrix.recipes.filter((value): value is string => typeof value === 'string')
          : [];
        const matrixRoutes = matrix.kind === 'native'
          ? (Array.isArray(matrix.routes) ? matrix.routes : [])
          : (Array.isArray(matrix.toolchains) ? matrix.toolchains : []);
        const matrixFactors = Array.isArray(matrix.factor_variants)
          ? matrix.factor_variants
          : plan.coverage.factor_variants;
        for (const recipeRef of recipeRefs) {
          const recipeName = recipeRef.split('@', 1)[0];
          recipes.add(recipeName);
          routes[recipeName] = Array.from(new Set([
            ...(routes[recipeName] ?? []),
            ...matrixRoutes.filter((value): value is string => typeof value === 'string'),
          ]));
          factors[recipeName] = Array.from(new Set([
            ...(factors[recipeName] ?? []),
            ...matrixFactors.filter((value): value is string => typeof value === 'string'),
          ]));
        }
      }
    }
    return { recipes: [...recipes], routes, factors, strategy };
  })();
  const selectedRecipes = selectedRecipesOverride ?? authorityDefaults.recipes;
  const routeSelections = routeSelectionsOverride ?? authorityDefaults.routes;
  const factorSelections = factorSelectionsOverride ?? authorityDefaults.factors;
  const queueStrategy = queueStrategyOverride ?? authorityDefaults.strategy ?? 'recipe-then-variant';
  const batchRank = (batchId: string) => {
    const rank = batchOrder.indexOf(batchId);
    return rank < 0 ? Number.MAX_SAFE_INTEGER : rank;
  };
  const scopedRecipeOptions = selectedLanguageId === 'c' ? recipeOptions : [];
  const orderedRecipeOptions = [...scopedRecipeOptions].sort((left, right) => batchRank(left.batch) - batchRank(right.batch));
  const selectedRecipeRows = orderedRecipeOptions.filter(recipe => recipe.planEligible && selectedRecipes.includes(recipe.id));
  const inspected = scopedRecipeOptions.find(recipe => recipe.id === inspectedRecipe);
  const inspectedCatalogFactor = catalogFactorGroups.flatMap(group => group.options).find(option => option.id === inspectedFactor);
  const inspectedFactorGroup = catalogFactorGroups.find(group => group.options.some(option => option.id === inspectedFactor));
  const libraryGroups = batchOrder.map(batchId => {
    const batch = rows.find(row => row.id === batchId);
    return {
      id: batchId,
      label: batch?.name || batchId,
      note: `${batch?.status || 'Unknown'} · ${batch?.progress || 'no progress'}`,
      rows: orderedRecipeOptions.filter(recipe => recipe.batch === batchId),
    };
  }).concat(orderedRecipeOptions.some(recipe => recipe.batch === 'unassigned') ? [{
    id: 'unassigned',
    label: 'Unassigned reviewed subjects',
    note: 'Catalogued authority · not present in the active priority queue',
    rows: orderedRecipeOptions.filter(recipe => recipe.batch === 'unassigned'),
  }] : []);
  const completedCellIds = new Set([
    ...builtCellIds,
    ...(factory.snapshot?.jobs ?? [])
      .filter(job => job.state === 'complete')
      .map(job => job.base_cell),
  ]);
  const cellRoute = (cellId: string) => cellId.split(':').at(-2) ?? 'unknown-route';
  const cellTreatment = (cellId: string) => cellId.split(':').at(-1) ?? 'unknown-treatment';
  const frozenWidthByRecipe = new Map<string, WidthCompilation[]>();
  for (const compilation of authority?.width_compilations ?? []) {
    if (!compilation.freeze) continue;
    const recipeName = compilation.fixed_recipe.split('@', 1)[0];
    frozenWidthByRecipe.set(recipeName, [
      ...(frozenWidthByRecipe.get(recipeName) ?? []),
      compilation,
    ]);
  }
  const builtWidthRows = recipeOptions.map(recipe => {
    const cellIds = [...completedCellIds].filter(cellId => (
      cellMatchesRecipe(cellId, recipe.name, recipe.version)
    ));
    const frozen = frozenWidthByRecipe.get(recipe.name) ?? [];
    const measuredRuns = (factory.laneInventory?.width_runs ?? [])
      .filter(run => (
        run.state === 'measured-complete'
        && run.fixed_recipe?.split('@', 1)[0] === recipe.name
      ))
      .sort((left, right) => right.completed_executions - left.completed_executions);
    const widestMeasuredRun = measuredRuns[0];
    const measuredCompilation = authority?.width_compilations.find(compilation => (
      compilation.id === widestMeasuredRun?.width_id
    ));
    const measuredTreatmentCount = new Set(
      (measuredCompilation?.build_profiles ?? [])
        .map(profile => profile.execution_treatment)
        .filter((value): value is string => Boolean(value)),
    ).size;
    const measuredPairCount = widestMeasuredRun?.successful_route_profile_pairs ?? 0;
    const measuredRouteCount = measuredTreatmentCount > 0
      && measuredPairCount % measuredTreatmentCount === 0
      ? measuredPairCount / measuredTreatmentCount
      : 0;
    const frozenCells = frozen.reduce((total, compilation) => (
      total + (compilation.freeze?.completed_executions ?? 0)
    ), 0);
    const frozenRoutes = new Set(frozen.flatMap(compilation => (
      compilation.routes.map(route => route.id)
    )));
    const frozenTreatments = new Set(frozen.flatMap(compilation => (
      compilation.build_profiles
        .map(profile => profile.execution_treatment)
        .filter((value): value is string => Boolean(value))
    )));
    return {
      recipe,
      cells: Math.max(cellIds.length, frozenCells, measuredPairCount),
      routes: Math.max(new Set(cellIds.map(cellRoute)).size, frozenRoutes.size, measuredRouteCount),
      treatments: Math.max(
        new Set(cellIds.map(cellTreatment)).size,
        frozenTreatments.size,
        measuredTreatmentCount,
      ),
      sources: [
        cellIds.length ? 'ledger / sealed inventory' : null,
        frozen.length ? `${frozen.length} frozen width run${frozen.length === 1 ? '' : 's'}` : null,
        widestMeasuredRun
          ? `${widestMeasuredRun.completed_executions} measured executions · ${measuredPairCount} unique route/profile pairs`
          : null,
      ].filter((value): value is string => Boolean(value)),
    };
  }).filter(row => row.cells > 0)
    .sort((left, right) => right.cells - left.cells || left.recipe.name.localeCompare(right.recipe.name));
  const scheduledBatchRows = batchOrder.filter(batchId => (
    factory.snapshot?.batches.some(batch => batch.id === batchId)
  )).map((batchId, index) => {
    const batch = factory.snapshot?.batches.find(row => row.id === batchId);
    const batchJobs = (factory.snapshot?.jobs ?? []).filter(job => job.batch_id === batchId);
    const recipeNamesFromJobs = recipeOptions
      .filter(recipe => batchJobs.some(job => cellMatchesRecipe(job.base_cell, recipe.name, recipe.version)))
      .map(recipe => recipe.name);
    const recipeNames = recipeNamesFromJobs.length
      ? recipeNamesFromJobs
      : recipeOptions.filter(recipe => recipe.batch === batchId).map(recipe => recipe.name);
    const stateCounts = batchJobs.reduce<Record<string, number>>((counts, job) => ({
      ...counts,
      [job.state]: (counts[job.state] ?? 0) + 1,
    }), {});
    const queued = (stateCounts.queued ?? 0) + (stateCounts.leased ?? 0) + (stateCounts.running ?? 0);
    return {
      id: batchId,
      position: batch?.position ?? index + 1,
      label: batch?.name ?? rows.find(row => row.id === batchId)?.name ?? batchId,
      planPath: batch?.plan_path ?? rows.find(row => row.id === batchId)?.note ?? 'plans/priority-queue.toml',
      recipeNames,
      jobs: batchJobs.length,
      complete: stateCounts.complete ?? 0,
      failed: (stateCounts.failed ?? 0) + (stateCounts.blocked ?? 0),
      queued,
    };
  }).sort((left, right) => left.position - right.position);
  const nextScheduledBatchId = scheduledBatchRows.find(row => row.queued > 0)?.id ?? null;
  const unscheduledRecipes = recipeOptions.filter(recipe => (
    recipe.planEligible && recipe.batch === 'unassigned'
  ));
  const missingRecipeFamilies = (widthStudy?.families ?? []).filter(family => (
    family.recipe_state !== 'reviewed-recipe' || family.recipe_ids.length === 0
  ));
  const missingToolchainRequirements = (widthStudy?.toolchain_requirements ?? []).filter(requirement => (
    requirement.native_route_ids.length === 0
    && requirement.source_capable_toolchain_ids.length === 0
  ));
  const combinationsForRecipe = (recipeId: string) => {
    const selectedRows = allFactorOptions.filter(option => (factorSelections[recipeId] || []).includes(option.id));
    const dimensions = selectedRows.reduce<Record<string, typeof selectedRows>>((groups, option) => {
      (groups[option.factor] ||= []).push(option);
      return groups;
    }, {});
    return Object.values(dimensions).reduce<Array<Array<(typeof selectedRows)[number]>>>((combinations, options) => combinations.flatMap(combination => options.map(option => [...combination, option])), [[]]);
  };
  const inventoryForRoute = (recipe: RecipeOption, routeId: string) => {
    const toolchain = toolchainOptions.find(row => row.id === routeId);
    const routeToken = toolchain ? `:${toolchain.variant}` : `:${routeId}:`;
    const matches = inventoryCells.filter(([cellId]) => (
      cellMatchesRecipe(cellId, recipe.name, recipe.version)
      && cellId.includes(routeToken)
    ));
    if (matches.some(([, inventory]) => inventory.state === 'built')) return 'built';
    if (matches.some(([, inventory]) => inventory.state === 'artifact-only')) return 'artifact-only';
    return 'not-built';
  };
  const routeIsCompatible = (recipe: RecipeOption, routeId: string) => {
    if (recipe.mode === 'native') {
      return nativeRouteOptions.some(route => route.id === routeId);
    }
    const toolchain = toolchainOptions.find(row => row.id === routeId);
    return Boolean(
      toolchain
      && toolchain.sourceCapable
      && toolchain.family === recipe.toolchainFamily
      && (!recipe.toolchainVariants?.length || recipe.toolchainVariants.includes(toolchain.variant)),
    );
  };
  const cells = selectedRecipeRows.flatMap(recipe => (routeSelections[recipe.id] || []).flatMap(routeId => {
    const nativeRoute = nativeRouteOptions.find(row => row.id === routeId);
    if (nativeRoute && recipe.mode === 'native') return [{
      id: `${recipe.id}:${routeId}`,
      recipeId: recipe.id,
      recipe: `${recipe.name} ${recipe.version}`,
      batch: recipe.batch,
      target: nativeRoute.target,
      toolchain: nativeRoute.compiler,
      treatment: 'baseline_o2',
      analysis: nativeRoute.analysis,
      status: 'planned',
      route: 'native-local',
      coverage: inventoryForRoute(recipe, routeId),
    }];
    const toolchain = toolchainOptions.find(row => row.id === routeId);
    if (!toolchain || recipe.mode === 'native') return [];
    return [{
      id: `${recipe.id}-${toolchain.id}`, recipeId: recipe.id, recipe: `${recipe.name} ${recipe.version}`, batch: recipe.batch, target: toolchain.abi,
      toolchain: toolchain.compiler, treatment: recipe.mode === 'malware' ? (recipe.adapter ?? 'reviewed adapter') : 'adapter-owned',
      analysis: toolchain.language, status: routeIsCompatible(recipe, routeId) ? 'planned' : 'blocked', route: executor,
      coverage: inventoryForRoute(recipe, routeId),
    }];
  }));
  const unorderedQueuePairs = cells.flatMap(cell => combinationsForRecipe(cell.recipeId).map(combination => ({ cell, combination })));
  const queuePairs = queueStrategy === 'recipe-then-variant' ? unorderedQueuePairs : [...unorderedQueuePairs].sort((left, right) => left.combination.map(option => option.id).join('|').localeCompare(right.combination.map(option => option.id).join('|')) || cells.indexOf(left.cell) - cells.indexOf(right.cell));
  const executionQueue = queuePairs.map((item, index) => {
    const unsupported = item.combination.some(option => option.state !== 'registered');
    return { ...item, position: index + 1, state: item.cell.status === 'blocked' || unsupported ? 'blocked' : 'queueable' };
  });
  const desiredCellCount = executionQueue.length;
  const plannedCells = executionQueue.filter(row => row.state === 'queueable').length;
  const blockedCells = Math.max(0, desiredCellCount - plannedCells);
  const builtExecutions = executionQueue.filter(row => row.cell.coverage === 'built').length;
  const malwareRecipe = scopedRecipeOptions.find(recipe => recipe.mode === 'malware');
  const malwareInventory = malwareRecipe ? inventoryCells.filter(([cellId]) => (
    cellMatchesRecipe(cellId, malwareRecipe.name, malwareRecipe.version)
  )) : [];
  const measuredEtaNs = etaDuration(timing?.eta ?? null);
  const selectedFactorRows = allFactorOptions.filter(option => selectedRecipeRows.some(recipe => (factorSelections[recipe.id] || []).includes(option.id)));
  const toggleRecipe = (id: string) => {
    if (!scopedRecipeOptions.find(recipe => recipe.id === id)?.planEligible) return;
    setSelectedRecipesOverride(current => {
      const selected = current ?? selectedRecipes;
      return selected.includes(id) ? selected.filter(item => item !== id) : [...selected, id];
    });
  };
  const toggleRoute = (recipeId: string, routeId: string) => setRouteSelectionsOverride(current => {
    const selections = current ?? routeSelections;
    const selected = selections[recipeId] ?? [];
    return { ...selections, [recipeId]: selected.includes(routeId) ? selected.filter(item => item !== routeId) : [...selected, routeId] };
  });
  const toggleFactor = (recipeId: string, factorId: string) => setFactorSelectionsOverride(current => {
    const selections = current ?? factorSelections;
    const selected = selections[recipeId] ?? [];
    return { ...selections, [recipeId]: selected.includes(factorId) ? selected.filter(item => item !== factorId) : [...selected, factorId] };
  });
  const toggleVariableGroup = (id: string) => setCollapsedVariableGroups(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id]);
  const toggleLibraryGroup = (id: string) => setCollapsedLibraryGroups(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id]);
  const plannedRecipeRows = selectedRecipeRows.filter(recipe => (routeSelections[recipe.id] || []).length > 0);
  const displayedVariableGroups = matrixVariableGroups.map(group => ({
    ...group,
    collapsed: collapsedVariableGroups.includes(group.id),
    displayedOptions: collapsedVariableGroups.includes(group.id) ? [{ id: `${group.id}:summary`, label: `${group.options.length} variables`, detail: group.note, state: 'summary', compatible: ['native', 'source', 'malware'], kind: 'summary' }] : group.options,
  }));
  const matrixColumnCount = displayedVariableGroups.reduce((total, group) => total + group.displayedOptions.length, 0);
  const toml = [
    'schema_version = "fidb-plan/v1"',
    `name = "${draftName}"`,
    '',
    '[policy]',
    'max_cells = 256',
    'priority = "normal"',
    '',
    '[coverage]',
    'factor_variants = []',
    '',
    '[queue]',
    `strategy = "${queueStrategy}"`,
    'recipe_order = [',
    ...plannedRecipeRows.map(recipe => `  "${recipe.id}@${recipe.version}",`),
    ']',
    ...plannedRecipeRows.flatMap(recipe => {
      const factorLines = (factorSelections[recipe.id] || []).map(id => `  "${id}",`);
      if (recipe.mode === 'native') {
        const nativeRoutes = (routeSelections[recipe.id] || []).filter(id => (
          nativeRouteOptions.some(route => route.id === id)
        ));
        return ['', '[[matrix]]', `id = "${recipe.id}-native"`, 'kind = "native"', `recipes = ["${recipe.id}@${recipe.version}"]`, `routes = [${nativeRoutes.map(id => `"${id}"`).join(', ')}]`, 'treatments = ["baseline_o2"]', 'factor_variants = [', ...factorLines, ']'];
      }
      const toolchainLines = (routeSelections[recipe.id] || []).map(id => toolchainOptions.find(toolchain => toolchain.id === id)).filter((row): row is (typeof toolchainOptions)[number] => Boolean(row)).map(row => `  "${row.ref}",`);
      return ['', '[[matrix]]', `id = "${recipe.id}-cross"`, `kind = "${recipe.mode === 'malware' ? 'malware' : 'source-library'}"`, `recipes = ["${recipe.id}@${recipe.version}"]`, 'toolchains = [', ...toolchainLines, ']', `executor = "${executor}"`, 'factor_variants = [', ...factorLines, ']'];
    }),
  ].join('\n');
  const savedAuthorityDraft = authority?.plans.find(plan => (
    plan.path === `plans/drafts/${draftName}.toml`
  ));
  const draftIsCurrent = validatedToml === toml && draftResult !== null;
  const resolveDraft = async () => {
    try {
      const result = await factory.resolvePlanDraft(toml);
      setDraftResult(result);
      setValidatedToml(toml);
      setDraftMessage(`Resolved ${result.resolved.summary.desired_cells ?? 0} desired executions; digest ${result.resolved.plan_digest.slice(0, 12)}…`);
    } catch (error) {
      setDraftResult(null);
      setValidatedToml(null);
      setDraftMessage(error instanceof Error ? error.message : 'Draft resolution failed.');
    }
  };
  const saveDraft = async () => {
    if (!draftIsCurrent) return;
    try {
      const result = await factory.savePlanDraft(
        draftName,
        toml,
        savedDraftSha256 ?? savedAuthorityDraft?.toml_sha256,
      );
      setDraftResult(result);
      setValidatedToml(toml);
      setSavedDraftSha256(result.toml_sha256);
      setDraftMessage(`Saved ${result.path}; plan digest ${result.resolved.plan_digest.slice(0, 12)}…`);
    } catch (error) {
      setDraftMessage(error instanceof Error ? error.message : 'Draft save failed.');
    }
  };
  return (
    <div className="view-stack">
      <ViewIntro kicker="ANALYST MATRIX" title={`${selectedLanguage?.label ?? 'C'} coverage matrix`} action={<button className="secondary-action" onClick={() => setTomlOpen(!tomlOpen)} disabled={selectedLanguageId !== 'c'}>{selectedLanguageId === 'c' ? `${tomlOpen ? 'Hide' : 'Show'} TOML` : 'No executable draft'}</button>} />

      <LanguageScopeSelector languages={coverageUniverse?.languages ?? []} selectedId={selectedLanguageId} onSelect={setSelectedLanguageId} />

      {selectedLanguageId === 'c' && authority?.cohort_validation && (
        <CohortValidationLifecyclePanel lifecycle={authority.cohort_validation} />
      )}

      {selectedLanguageId === 'c' && authority?.campaign_programmes.map(programme => (
        <CampaignProgrammePanel
          key={programme.id}
          programme={programme}
          lifecycle={authority.cohort_validation?.programmes.find(row => row.id === programme.id)}
        />
      ))}

      <section className="panel operational-matrix-index" aria-label="Operational matrix build order">
        <header>
          <h3>Operational matrix</h3>
          <div className="operational-matrix-counts"><span><b>{builtWidthRows.length}</b> built subjects</span><span><b>{scheduledBatchRows.length}</b> ordered batches</span><span><b>{qualificationPipeline ? `${qualificationPipeline.summary.satisfied}/${qualificationPipeline.summary.batches}` : '—'}</b> qualification gates</span><span><b>{unscheduledRecipes.length}</b> buildable / unscheduled</span><span><b>{missingRecipeFamilies.length}</b> recipe gaps</span><span><b>{missingToolchainRequirements.length}</b> toolchain gaps</span></div>
        </header>

        <section className="operational-matrix-band built-band">
          <div className="operational-band-title"><b>01</b><span><strong>Already built</strong><small>Sealed evidence, with achieved width—not declared possibility.</small></span><em>{builtWidthRows.reduce((total, row) => total + row.cells, 0).toLocaleString()} cells</em></div>
          <div className="operational-built-list">
            {builtWidthRows.map(row => <article key={row.recipe.id}><span className="operational-state built">BUILT</span><p><strong>{row.recipe.name} {row.recipe.version}</strong><small>{row.sources.join(' · ')}</small></p><dl><div><dt>CELLS</dt><dd>{row.cells}</dd></div><div><dt>ROUTES</dt><dd>{row.routes}</dd></div><div><dt>TREATMENTS</dt><dd>{row.treatments}</dd></div></dl></article>)}
            {!builtWidthRows.length && <div className="operational-empty"><strong>No sealed builds detected</strong><small>Declared routes and loose artifacts are deliberately not counted as built.</small></div>}
          </div>
        </section>

        <section className="operational-matrix-band scheduled-band">
          <div className="operational-band-title"><b>02</b><span><strong>Scheduled next</strong><small>Exact execution order from plans/priority-queue.toml and its synchronized ledger.</small></span><em>{scheduledBatchRows.reduce((total, row) => total + row.jobs, 0).toLocaleString()} cells</em></div>
          <ol className="operational-batch-list">
            {scheduledBatchRows.map(row => {
              const complete = row.jobs > 0 && row.complete === row.jobs;
              const state = complete ? 'complete' : row.id === nextScheduledBatchId ? 'next' : row.failed > 0 && row.queued === 0 ? 'blocked' : 'scheduled';
              return <li className={state} key={row.id}><b>{String(row.position).padStart(2, '0')}</b><span className={`operational-state ${state}`}>{state === 'next' ? 'NEXT' : state.toUpperCase()}</span><p><strong>{row.label}</strong><small>{row.recipeNames.join(' + ') || row.planPath}</small></p><div><span><b>{row.complete}</b> complete</span><span><b>{row.queued}</b> remaining</span>{row.failed > 0 && <span className="failed"><b>{row.failed}</b> failed / blocked</span>}</div></li>;
            })}
            {!scheduledBatchRows.length && <li className="empty"><p><strong>No active queue batches</strong><small>Add reviewed plan paths to the TOML queue; draft selections are not scheduled work.</small></p></li>}
          </ol>
        </section>

        {qualificationPipeline && <section className="operational-matrix-band qualification-band">
          <div className="operational-band-title"><b>03</b><span><strong>Campaign qualification</strong><small>Real compilation-only gate between reviewed recipes and queue-eligible campaign blocks.</small></span><em>{qualificationPipeline.summary.qualified} qualified · {qualificationPipeline.summary.blocked} blocked · enforced</em></div>
          <div className="operational-qualification-list">
            {qualificationPipeline.gates.map(gate => {
              const tone = gate.state === 'qualified' ? 'ready' : gate.state === 'historical-exempt' ? 'complete' : 'blocked';
              const label = gate.state === 'historical-exempt' ? 'HISTORICAL SEAL' : gate.state.replaceAll('-', ' ').toUpperCase();
              return <article key={gate.batch_id}><span className={`operational-state ${tone}`}>{label}</span><p><strong>{gate.batch_id}</strong><small>{gate.authority_path ?? gate.reason ?? 'qualification authority required'}{gate.blockers.length ? ` · ${gate.blockers.join(' · ')}` : ''}</small></p><div><b>{gate.summary.total ? `${gate.summary.built}/${gate.summary.total}` : '—'}</b><span>compile cells</span></div><div><b>{gate.satisfied ? gate.promotion_state.replaceAll('-', ' ') : 'campaign blocked'}</b><span>promotion</span></div></article>;
            })}
          </div>
        </section>}

        {machineValidation && <section className="operational-matrix-band validation-band">
          <div className="operational-band-title"><b>04</b><span><strong>Validation and hash discrimination</strong><small>Machine cohorts measure controlled width; held-out binaries test the corpus; HDI learns how strongly each compatible hash distinguishes provenance.</small></span><em>{machineValidation.summary.complete_libraries}/{machineValidation.summary.cohort_libraries} cohort · {ecologicalValidation?.summary.completed_cases ?? 0} ecological · HDI {hashDiscrimination?.summary.scored_signatures ?? '—'}</em></div>
          <div className="operational-validation-stack">
            <div className="operational-validation-row"><span className={`operational-state ${machineValidation.run.state === 'complete' ? 'ready' : ['queued', 'preparing-index', 'running', 'pausing', 'paused', 'interrupted'].includes(machineValidation.run.state) ? 'next' : machineValidation.readiness.eligible ? 'ready' : 'blocked'}`}>{['queued', 'preparing-index', 'running', 'pausing'].includes(machineValidation.run.state) ? machineValidation.run.state.replaceAll('-', ' ').toUpperCase() : ['paused', 'interrupted'].includes(machineValidation.run.state) ? 'PAUSED · RESUMABLE' : machineValidation.run.state === 'complete' ? 'MEASURED' : machineValidation.run.state === 'failed' && (machineValidation.run.expected_work_units ?? 0) > machineValidation.run.complete_work_units ? 'RETRY · RESUMABLE' : machineValidation.readiness.eligible ? 'READY TO RUN' : 'WAITING'}</span><p><strong>Machine validation · {machineValidation.id}</strong><small>{machineValidation.summary.exact_identities} live identities ({machineValidation.summary.width_delta_from_baseline >= 0 ? '+' : ''}{machineValidation.summary.width_delta_from_baseline} from baseline) · fixed RNG seed · {machineValidation.summary.composite_programs} composites</small></p><div><b>{machineValidation.run.expected_work_units ? `${machineValidation.run.complete_work_units}/${machineValidation.run.expected_work_units}` : machineValidation.summary.cohort_libraries - machineValidation.summary.complete_libraries}</b><span>{machineValidation.run.expected_work_units ? 'run units' : 'libraries to gate'}</span></div><div><b>{machineValidation.canary_gate.ready ? 'PASS' : `≈${machineValidation.planning.central_wall_hours.toFixed(0)}h`}</b><span>{machineValidation.canary_gate.ready ? 'canary gate' : 'planning wall'}</span></div></div>
            <div className="operational-validation-row"><span className={`operational-state ${ecologicalValidation?.corpus.materialized_generations ? 'ready' : 'blocked'}`}>{ecologicalValidation?.corpus.materialized_generations ? 'CORPUS READY' : 'NO CORPUS'}</span><p><strong>Ecological validation · held-out binaries</strong><small>{ecologicalValidation?.summary.imported_cases ?? 0} imports · {ecologicalValidation?.aggregate.measured_cases ?? 0} measured · entire compatible lane corpus · never execute imports</small></p><div><b>{ecologicalValidation?.aggregate.failure_summary.collisions ?? 0}</b><span>collisions</span></div><div><b>{ecologicalValidation?.aggregate.failure_summary.misses ?? 0}</b><span>misses</span></div></div>
            <div className="operational-validation-row"><span className={`operational-state ${hashDiscrimination?.readiness.ready_for_first_fit ? 'ready' : 'blocked'}`}>{hashDiscrimination?.readiness.ready_for_first_fit ? 'READY TO FIT' : 'WAITING HDI'}</span><p><strong>Hash Discrimination Index</strong><small>{hashDiscrimination?.readiness.complete_library_families ?? 0}/{hashDiscrimination?.readiness.required_library_families ?? 10} complete families · {noisyHashes?.summary.observed_hashes ?? 0} collision-bearing hashes · unweighted baseline preserved · no automatic filtering</small></p><div><b>{hashDiscrimination?.summary.scored_signatures ?? '—'}</b><span>scored hashes</span></div><div><b>{noisyHashes?.summary.confirmed_noisy ?? 0}</b><span>confirmed noisy</span></div></div>
          </div>
        </section>}

        <section className="operational-matrix-band retention-band">
          <div className="operational-band-title"><b>05</b><span><strong>Retention & garbage collection</strong><small>Terminal queue or validation → verified dry-run → bounded collection → worker recycle → memory audit.</small></span><em>{retention?.latest_plan ? `${retention.latest_plan.summary.actions.toLocaleString()} actions · ${formatBytes(retention.latest_plan.summary.recoverable_apparent_bytes)}` : 'awaiting dry-run'}</em></div>
          <div className="operational-retention-row"><span className={`operational-state ${retention?.latest_plan?.automatic_apply_eligible ? 'ready' : 'blocked'}`}>{retention?.latest_plan ? retention.latest_plan.automatic_apply_eligible ? 'AUTO ELIGIBLE' : 'MANUAL REVIEW' : 'NOT PLANNED'}</span><p><strong>{retention?.policy.authority_path ?? 'retention/policy.toml'}</strong><small>{retention?.latest_plan ? `${retention.latest_plan.summary.verified_successes.toLocaleString()} seals verified · ${retention.latest_plan.summary.preserved.toLocaleString()} protected · ${retention.latest_plan.summary.quarantined.toLocaleString()} quarantined` : 'content-addressed plan required before deletion'}</small></p><div><b>{retention?.latest_plan ? formatDurationNs(retention.latest_plan.estimated_apply_seconds * 1_000_000_000) : '—'}</b><span>estimated apply</span></div><div><b>{retention?.memory_cleanup.latest_session?.workers ? `${retention.memory_cleanup.latest_session.passed ?? 0}/${retention.memory_cleanup.latest_session.workers}` : '—'}</b><span>memory audits pass</span></div></div>
        </section>

        <div className="operational-gap-grid">
          <section className="operational-matrix-band unscheduled-band">
            <div className="operational-band-title"><b>06</b><span><strong>Buildable but unscheduled</strong><small>A reviewed recipe and source-capable route exist, but no active queue batch selects them.</small></span><em>{unscheduledRecipes.length}</em></div>
            <div className="operational-compact-list">
              {unscheduledRecipes.map(recipe => <article key={recipe.id}><span className="operational-state ready">READY</span><p><strong>{recipe.name} {recipe.version}</strong><small>{recipe.adapter} · {recipe.coverage}</small></p></article>)}
              {!unscheduledRecipes.length && <div className="operational-empty"><strong>No reviewed recipe is stranded</strong><small>Every currently buildable top-ten subject is represented in the active queue.</small></div>}
            </div>
          </section>

          <section className="operational-matrix-band recipe-gap-band">
            <div className="operational-band-title"><b>07</b><span><strong>No recipe yet</strong><small>Ranked family and source evidence exist, but no reviewed build recipe does.</small></span><em>{missingRecipeFamilies.length}</em></div>
            <div className="operational-compact-list">
              {missingRecipeFamilies.map(family => <article key={family.id}><span className="operational-state gap">RECIPE GAP</span><p><strong>#{family.rank} {family.label}</strong><small>{family.source_state} · {family.selection_evidence}</small></p></article>)}
              {!missingRecipeFamilies.length && <div className="operational-empty"><strong>Top-ten recipe set complete</strong><small>The broader C-family census is not promoted into this executable matrix until its family rows and source evidence are registered.</small></div>}
            </div>
          </section>

          <section className="operational-matrix-band toolchain-gap-band">
            <div className="operational-band-title"><b>08</b><span><strong>No executable toolchain yet</strong><small>Target/compiler demand exists, but neither an installed native route nor a source-capable cross route is registered.</small></span><em>{missingToolchainRequirements.length}</em></div>
            <div className="operational-compact-list">
              {missingToolchainRequirements.map(requirement => <article key={requirement.id}><span className="operational-state gap">{requirement.route_state.replaceAll('-', ' ')}</span><p><strong>{requirement.target_label} · {requirement.compiler_label}</strong><small>#{requirement.order} · {requirement.acquisition} · {requirement.worker_class}</small></p></article>)}
              {!missingToolchainRequirements.length && <div className="operational-empty"><strong>No toolchain gaps in the selected width</strong><small>Every demanded target/compiler pair has an executable route authority.</small></div>}
            </div>
          </section>
        </div>
        <footer><span>BUILT</span> means sealed output. <span>SCHEDULED</span> means present in the active TOML queue. <span>READY</span> means buildable but not queued. Gaps remain visible until their recipe or toolchain authority exists.</footer>
      </section>

      {selectedLanguage && <details className="panel matrix-detail-section" onToggle={event => setScopeOpen(event.currentTarget.open)}><summary><span><b>Scope and denominator</b><small>{selectedLanguage.label} family boundary, caveat and treatment-axis vocabulary</small></span><em>EXPAND</em></summary>{scopeOpen && <section className="language-matrix-contract"><div><span className={`language-state ${selectedLanguage.state}`}>{selectedLanguage.state.replaceAll('-', ' ')}</span><p className="panel-kicker">{selectedLanguage.label.toUpperCase()} DENOMINATOR</p><h3>{selectedLanguage.scope}</h3><p>{selectedLanguage.denominator}</p><small>{selectedLanguage.caveat}</small></div><div><span>TREATMENT AXES</span><div>{selectedLanguage.treatment_axes.map(axis => <em key={axis}>{axis}</em>)}</div></div></section>}</details>}

      {widthStudy && <details className="panel matrix-detail-section" onToggle={event => setWidthLaboratoryOpen(event.currentTarget.open)}><summary><span><b>Width laboratory and applicability map</b><small>{widthStudy.family_count} ranked families · {widthCompilation?.summary.executable_route_profile_pairs ?? 0} executable route/profile pairs · scaling controls</small></span><em>EXPAND</em></summary>{widthLaboratoryOpen && <WidthStudyPanel key={widthStudy.id} study={widthStudy} compilation={widthCompilation} capabilities={factory.capabilities} />}</details>}

      {selectedLanguageId !== 'c' && <div className="inline-warning language-registration-warning">The {selectedLanguage?.label} matrix is defined conceptually, but no screened family denominator, finite profile pack or executable recipe rows are registered. The empty rows below are deliberate—not zero coverage.</div>}

      <section className="plan-source-bar">
        <div><span className="source-glyph">T</span><p><strong>{selectedLanguageId === 'c' ? 'plans/priority-queue.toml' : `${selectedLanguage?.label ?? selectedLanguageId} execution authority not registered`}</strong><small>{selectedLanguageId === 'c' ? 'fidb-queue/v1 · batch order points to immutable fidb-plan/v1 requests' : 'conceptual language matrix · no queue cells or executable recipes'}</small></p></div>
        <span className="authority-badge">{selectedLanguageId === 'c' ? 'PRIORITY AUTHORITY' : 'DESIGN SCOPE'}</span>
      </section>

      <details className="panel matrix-detail-section crosspoint-drilldown" onToggle={event => setCrosspointOpen(event.currentTarget.open)}><summary><span><b>Full variable crosspoint and plan-draft editor</b><small>Cell-level families × routes × compilers × treatments × admission. Open only when you need to inspect or draft exact cells.</small></span><em>EXPAND</em></summary>{crosspointOpen && <div className="matrix-workspace">
        <section className="panel crosspoint-matrix-panel">
          <div className="matrix-main-header"><h2>Coverage crosspoints</h2><div className="matrix-live-summary"><span>RAW TREATMENT SPACE <strong>{rawNamedTreatmentSpace ? rawNamedTreatmentSpace.toLocaleString() : '—'}</strong><small>{selectedLanguageId === 'c' ? 'named C tuples / target / release; not a run plan' : 'finite profile pack not qualified'}</small></span><span>CANDIDATE PROFILES <strong>{languageProfiles.length || '—'}</strong><small>language-scoped · assumptions labelled</small></span><span>TARGET CONTEXTS <strong>{authority?.targets.length ?? '—'}</strong><small>{executableTargetCount} have a registered source route</small></span><span>DRAFT EXECUTIONS <strong>{desiredCellCount}</strong><small>TOML intent</small></span><span>QUEUEABLE <strong>{plannedCells}</strong><small>{selectedLanguageId === 'c' ? `${knownFactorCount} known factors · ${measuredFactorCount} observed` : 'no executable language pack'}</small></span><span>BUILT EVIDENCE <strong>{selectedLanguageId === 'c' ? builtCellIds.size : '—'}</strong><small>sealed cells · not yet coverage</small></span><span>ADMITTED COVERAGE <strong>—</strong><small>admission ledger not projected</small></span></div></div>
          <div className="matrix-toolbar">
            <div className="matrix-layer-control"><span>SHOW</span>{(['both', 'plan', 'inventory'] as const).map(layer => <button key={layer} className={matrixLayer === layer ? 'active' : ''} onClick={() => setMatrixLayer(layer)}>{layer === 'both' ? 'Plan + built' : layer}</button>)}</div>
            <div className="matrix-executor-control"><span>WORKER POOL</span><button className="active warning" disabled>Library local</button><small>native + explicit local cross-build · no QEMU</small></div>
            <div className="matrix-fold-control"><button onClick={() => setCollapsedVariableGroups([])}>Expand variables</button><button onClick={() => setCollapsedVariableGroups(matrixVariableGroups.map(group => group.id))}>Collapse variables</button><button onClick={() => setCollapsedLibraryGroups([])}>Expand batches</button></div>
          </div>
          <div className="inline-warning matrix-warning">Local library execution keeps the pinned source archive, exact cross-toolchain, reviewed adapter, flags and target ABI. No virtual machine is booted.</div>
          <div className="matrix-scroll" role="region" aria-label="Library and build variable matrix" tabIndex={0}>
            <table className="crosspoint-table">
              <thead><tr className="matrix-group-head"><th className="matrix-corner matrix-order" rowSpan={2}>#</th><th className="matrix-corner matrix-library" rowSpan={2}>Libraries / match sets</th><th className="matrix-corner matrix-batch" rowSpan={2}>Batch / inventory</th>{displayedVariableGroups.map(group => <th colSpan={group.displayedOptions.length} key={group.id}><button onClick={() => toggleVariableGroup(group.id)} aria-expanded={!group.collapsed}><span>{group.collapsed ? '▸' : '▾'}</span>{group.label}<small>{group.collapsed ? `${group.options.length} hidden` : group.note}</small></button></th>)}</tr><tr className="matrix-variable-head">{displayedVariableGroups.flatMap(group => group.displayedOptions.map(column => <th key={column.id} className={column.kind === 'summary' ? 'summary-column' : ''}><span>{column.label}</span><small>{column.detail}</small></th>))}</tr></thead>
              <tbody>{libraryGroups.map((group, groupIndex) => {
                const collapsed = collapsedLibraryGroups.includes(group.id);
                const familyGroups = Array.from(new Set(group.rows.map(recipe => recipe.familyGroup)));
                const batch = rows.find(row => row.id === group.id);
                return <Fragment key={group.id}><tr className={batch?.tier === 'T0' ? 'matrix-batch-group tier-zero' : 'matrix-batch-group'}><th colSpan={3 + matrixColumnCount}><button onClick={() => toggleLibraryGroup(group.id)} aria-expanded={!collapsed}><span>{collapsed ? '▸' : '▾'}</span><b>{String(groupIndex + 1).padStart(2, '0')} · {batch?.tier ? `${batch.tier} · ` : ''}{group.id}</b><strong>{group.label}</strong><small>{group.note} · {group.rows.length} subject rows</small></button></th></tr>{!collapsed && !group.rows.length && <tr className="matrix-deferred-row"><th colSpan={3}>Later batch · no catalog rows loaded</th><td colSpan={matrixColumnCount}>This batch remains in priority order and will populate when its resolved match set is loaded.</td></tr>}{!collapsed && familyGroups.map(familyGroup => <Fragment key={`${group.id}-${familyGroup}`}><tr className="matrix-match-group"><th colSpan={3}><span>↳</span>{familyGroup}</th><td colSpan={matrixColumnCount}>{Array.from(new Set(group.rows.filter(recipe => recipe.familyGroup === familyGroup).map(recipe => recipe.matchSet))).join(' · ')}</td></tr>{group.rows.filter(recipe => recipe.familyGroup === familyGroup).map(recipe => {
                  const recipeSelected = selectedRecipes.includes(recipe.id);
                  const order = selectedRecipeRows.findIndex(row => row.id === recipe.id);
                  const recipeBatch = rows.find(row => row.id === recipe.batch);
                  return <tr className={recipeSelected ? 'matrix-library-row selected' : 'matrix-library-row'} key={recipe.id}><th className="matrix-order"><button onClick={() => toggleRecipe(recipe.id)} disabled={!recipe.planEligible} aria-pressed={recipeSelected} title={recipe.planEligible ? 'Add or remove this reviewed recipe from the queue draft' : 'Coverage subject is blocked until a reviewed recipe and route exist'}>{recipe.planEligible ? (recipeSelected ? String(order + 1).padStart(2, '0') : '+') : '!'}</button></th><th className="matrix-library"><div><strong>{recipe.name}</strong><em>{recipe.version}</em><small>{recipe.detail}</small></div><button onClick={() => setInspectedRecipe(recipe.id)}>{recipe.planEligible ? 'PROV' : 'GAP'}</button></th><th className="matrix-batch"><span className={`batch-status ${recipeBatch?.status.toLowerCase()}`}>{recipe.batch}</span><small>{recipeBatch?.status || 'assigned'}{recipeBatch?.status === 'Defined' ? ' · not submitted' : ''}</small><b className={`inventory-state ${recipe.readiness}`}>{recipe.coverage}</b></th>{displayedVariableGroups.flatMap(variableGroup => variableGroup.displayedOptions.map(column => {
                    const catalogOnly = !recipe.planEligible;
                    const routeRelevant = column.kind === 'route' && (
                      recipe.mode === 'native'
                        ? nativeRouteOptions.some(route => route.id === column.id)
                        : toolchainOptions.some(toolchain => (
                          toolchain.id === column.id
                          && toolchain.family === recipe.toolchainFamily
                          && (!recipe.toolchainVariants?.length || recipe.toolchainVariants.includes(toolchain.variant))
                        ))
                    );
                    const possibilityOnly = column.kind === 'target' || column.kind === 'profile';
                    const compatible = column.kind === 'summary'
                      || column.kind === 'catalog'
                      || possibilityOnly
                      || (column.kind === 'route' && routeIsCompatible(recipe, column.id))
                      || (column.kind === 'factor' && recipe.mode === 'native' && recipe.planEligible);
                    const requested = recipeSelected && (column.kind === 'route' ? (routeSelections[recipe.id] || []).includes(column.id) : column.kind === 'factor' ? (factorSelections[recipe.id] || []).includes(column.id) : false);
                    const inventory = column.kind === 'route' && routeRelevant
                      ? inventoryForRoute(recipe, column.id)
                      : 'not-built';
                    const routeToken = toolchainOptions.find(toolchain => toolchain.id === column.id)?.variant;
                    const liveJob = column.kind === 'route' ? factory.snapshot?.jobs.find(job => (
                      cellMatchesRecipe(job.base_cell, recipe.name, recipe.version)
                      && (routeToken ? job.base_cell.includes(`:${routeToken}`) : job.base_cell.includes(`:${column.id}:`))
                    )) : undefined;
                    const unsupported = column.state === 'gap' || (column.kind === 'factor' && column.state !== 'registered');
                    let state = compatible || routeRelevant ? 'unbuilt' : 'unavailable';
                    if (column.kind === 'catalog' || possibilityOnly) state = column.state;
                    else if (column.kind === 'summary') state = 'summary';
                    else if (column.kind === 'route' && routeRelevant && !compatible) state = 'blocked';
                    else if (catalogOnly && column.kind !== 'route') state = 'blocked';
                    else if (matrixLayer === 'inventory') state = inventory;
                    else if (requested && unsupported) state = 'blocked';
                    else if (matrixLayer === 'both' && inventory === 'built') state = 'built';
                    else if (matrixLayer === 'both' && inventory === 'artifact-only') state = 'artifact-only';
                    else if (requested && (liveJob?.state === 'running' || liveJob?.state === 'leased')) state = 'running';
                    else if (requested && liveJob?.state === 'queued') state = 'queued';
                    else if (requested && (liveJob?.state === 'blocked' || liveJob?.state === 'failed')) state = 'blocked';
                    else if (requested) state = 'selected';
                    const action = () => {
                      if (column.kind === 'summary') return toggleVariableGroup(variableGroup.id);
                      if (column.kind === 'catalog') return setInspectedFactor(column.id);
                      if (possibilityOnly) return;
                      if (!compatible || catalogOnly) return setInspectedRecipe(recipe.id);
                      if (!recipeSelected) setSelectedRecipesOverride(current => [...(current ?? selectedRecipes), recipe.id]);
                      if (column.kind === 'route') toggleRoute(recipe.id, column.id);
                      else toggleFactor(recipe.id, column.id);
                    };
                    return <td className={`matrix-point-cell ${state}`} key={`${recipe.id}-${column.id}`}><button onClick={action} disabled={(!compatible && !routeRelevant) || possibilityOnly} aria-pressed={requested} title={`${recipe.name} × ${column.label}: ${catalogOnly && state === 'blocked' ? 'desired gap' : state}. ${catalogOnly ? recipe.gap : column.detail}`}><span>{state === 'unavailable' ? '—' : state === 'blocked' ? '!' : state === 'artifact-only' ? '◐' : state === 'built' ? '■' : state === 'running' ? '▶' : state === 'executable' ? 'E' : state === 'conceptual' ? 'C' : state === 'catalogued' ? 'K' : state === 'desired' ? 'D' : state === 'guarded' ? 'G' : state === 'observed' ? 'O' : state === 'recorded' ? '●' : state === 'unmodeled' ? '?' : state === 'summary' ? (column.kind === 'summary' ? (variableGroup.options.filter(option => option.kind === 'catalog' || (option.kind === 'route' ? (routeSelections[recipe.id] || []).includes(option.id) : (factorSelections[recipe.id] || []).includes(option.id))).length || '·') : '·') : requested ? '■' : '·'}</span></button></td>;
                  }))}</tr>;
                })}</Fragment>)}</Fragment>;
              })}</tbody>
            </table>
          </div>
          <div className="matrix-legend"><span><i className="conceptual" /> conceptual context</span><span><i className="catalogued" /> catalogued</span><span><i className="executable" /> executable route exists</span><span><i className="selected" /> selected</span><span><i className="queued" /> queued</span><span><i className="running" /> running</span><span><i className="built" /> sealed built</span><span><i className="blocked" /> blocked / guarded</span><span><i className="unavailable" /> incompatible</span><p>Possibility-space markers are not queue cells. Built means evidence-backed output, never merely a declared target.</p></div>
          {inspectedCatalogFactor && <aside className="matrix-factor-inspector"><div><span>KNOWN SENSITIVITY FACTOR</span><button onClick={() => setInspectedFactor(null)} aria-label="Close factor detail">×</button></div><h3>{inspectedCatalogFactor.label}</h3><p>{inspectedCatalogFactor.detail}</p><dl><div><dt>Catalogue ID</dt><dd>{inspectedCatalogFactor.id}</dd></div><div><dt>Group</dt><dd>{inspectedFactorGroup?.label || 'Sensitivity'}</dd></div><div><dt>Matrix status</dt><dd>{inspectedCatalogFactor.state === 'recorded' ? 'Recorded in resolved-cell provenance' : 'Known factor; no named selectable variant yet'}</dd></div><div><dt>Authority</dt><dd>sensitivity/factors.toml</dd></div></dl><small>The catalogue is intentionally extensible: report-backed factors are the current baseline, not a claim that every possible FID influence is already known.</small></aside>}
          {inspected && <aside className="recipe-provenance matrix-provenance"><div><span>{inspected.planEligible ? 'REVIEWED RECIPE PROVENANCE' : 'TIER 0 COVERAGE GAP'}</span><button onClick={() => setInspectedRecipe(null)} aria-label="Close provenance">×</button></div><h3>{inspected.name} <em>{inspected.version}</em></h3><p>{inspected.planEligible ? 'Immutable build identity comes from the reviewed recipe. Change the recipe TOML and re-resolve the plan to alter these fields.' : inspected.gap}</p><dl><div><dt>Authority</dt><dd>{inspected.authority}</dd></div><div><dt>Readiness</dt><dd>{inspected.coverage}</dd></div><div><dt>Batch / family</dt><dd>{inspected.batch} / {inspected.familyGroup}</dd></div><div><dt>Match context</dt><dd>{inspected.matchSet}</dd></div>{inspected.recipePath && <div><dt>Recipe</dt><dd>{inspected.recipePath}</dd></div>}{inspected.adapter && <div><dt>Mode / adapter</dt><dd>{inspected.mode} / {inspected.adapter}</dd></div>}{inspected.url && <div className="wide"><dt>Source URL</dt><dd>{inspected.url}</dd></div>}{inspected.sha256 && <div className="wide"><dt>SHA-256</dt><dd>{inspected.sha256}</dd></div>}</dl></aside>}
        </section>

        <aside className="plan-visualizer">
          <section className="panel cell-map-panel">
            <div className="panel-header"><h3>Execution map · {cells.length} base cells → {desiredCellCount} exact executions</h3><span className={blockedCells ? 'plan-state blocked' : 'plan-state ready'}>{blockedCells ? `${blockedCells} GAP` : 'COVERED'}</span></div>
            <div className="cell-summary"><div><span>DESIRED</span><strong>{desiredCellCount}</strong></div><div><span>QUEUEABLE</span><strong>{plannedCells}</strong></div><div><span>BLOCKED</span><strong>{blockedCells}</strong></div><div><span>OPTIONS</span><strong>{selectedFactorRows.length} / {allFactorOptions.length}</strong></div></div>
            <div className="cell-flow-head"><span>Recipe</span><span>Target + toolchain</span><span>Treatment</span><span>Analysis</span></div>
            <div className="visual-cell-list">
              {cells.map(cell => <div className={`visual-cell ${cell.status} ${cell.coverage || 'not-built'}`} key={cell.id}><span className="cell-status-icon">{cell.coverage === 'artifact-only' ? '◐' : cell.status === 'planned' ? '✓' : '!'}</span><div><strong>{cell.recipe}</strong><small>{cell.coverage === 'artifact-only' ? `artifact found · ${cell.batch}` : `${cell.route} · ${cell.batch}`}</small></div><b>→</b><div><strong>{cell.target}</strong><small>{cell.toolchain}</small></div><b>→</b><div><strong>{cell.treatment}</strong><small>× {combinationsForRecipe(cell.recipeId).length} exact factor tuples</small></div><b>→</b><div><strong>{cell.analysis}</strong><small>execution identity recorded</small></div></div>)}
              {!cells.length && <div className="empty-state"><span>◇</span><strong>No desired cells</strong><p>Select at least one recipe and compatible route.</p></div>}
            </div>
            {blockedCells > 0 && <div className="coverage-alert"><span>!</span><p><strong>Desired coverage is not silently discarded.</strong><small>{blockedCells} desired cells currently lack a registered treatment, source-capable toolchain, or guarded truth/admission path. They remain visible until those requirements exist.</small></p></div>}
          </section>

          <section className="panel malware-estimate-panel"><div className="panel-header"><h3>Timing evidence</h3><span className={timing?.eta ? 'plan-state ready' : 'plan-state'}>{timing?.eta ? 'MEASURED' : 'COLLECTING'}</span></div>{malwareRecipe ? <div className="malware-estimate-row"><span className="malware-glyph">M</span><div><strong>{malwareRecipe.name}</strong><small>{malwareRecipe.version} · {malwareRecipe.adapter}</small></div><p><span>KNOWN CELLS</span><strong>{malwareInventory.length}</strong></p><p><span>SEALED / LOOSE</span><strong>{malwareInventory.filter(([, row]) => row.state === 'built').length} / {malwareInventory.filter(([, row]) => row.state === 'artifact-only').length}</strong></p><p><span>QUEUE ETA</span><strong>{measuredEtaNs === null ? 'Collecting evidence' : formatDurationNs(measuredEtaNs)}</strong><small>{timing?.eta?.sample_count ? `${timing.eta.sample_count} measured workflows` : 'no historical estimate yet'}</small></p></div> : <div className="empty-state"><span>◇</span><strong>No reviewed ground-truth recipe</strong><p>Add one to the recipe authority before planning it.</p></div>}</section>

          <section className="panel execution-queue-panel"><div className="panel-header"><h3>Priority queue draft · batch × cell × variance</h3><span className="plan-state">TOML INTENT</span></div><div className="queue-controls single"><label><span>VARIANCE ORDER WITHIN EACH BATCH</span><select value={queueStrategy} onChange={event => setQueueStrategyOverride(event.target.value)}><option value="recipe-then-variant">recipe, then variance</option><option value="variant-then-recipe">variance, then recipe</option></select></label><button onClick={() => setQueueMessage(`Priority queue draft updated with ${executionQueue.length} execution identities in current batch order.`)}>Update priority queue draft</button></div>{queueMessage && <div className="queue-message">✓ {queueMessage}</div>}<div className="queue-state-summary"><div><span>QUEUEABLE</span><strong>{executionQueue.filter(row => row.state === 'queueable').length}</strong></div><div><span>BUILT</span><strong>{builtExecutions}</strong></div><div><span>ARTIFACT ONLY</span><strong>{cells.filter(cell => cell.coverage === 'artifact-only').length}</strong></div><div><span>UNBUILT / BLOCKED</span><strong>{executionQueue.filter(row => row.state === 'blocked').length}</strong></div></div><div className="execution-queue-list">{executionQueue.slice(0, 8).map(row => <div className={`execution-queue-row ${row.state}`} key={`${row.cell.id}-${row.position}`}><b>{String(row.position).padStart(3, '0')}</b><div><strong>{row.cell.recipe}</strong><small>{row.cell.target} · {row.combination.map(option => option.label).join(' / ') || 'route defaults'}</small></div><em>{row.cell.batch}</em><span>{row.cell.coverage === 'built' ? 'built' : row.cell.coverage === 'artifact-only' ? 'artifact only' : row.state}</span></div>)}{executionQueue.length > 8 && <div className="queue-remainder">+ {executionQueue.length - 8} more ordered execution identities</div>}</div></section>

          {tomlOpen && <section className="panel toml-panel"><div className="panel-header"><h3>TOML request</h3><span className={draftIsCurrent ? 'plan-state ready' : 'plan-state'}>{draftIsCurrent ? 'RESOLVED' : 'DRAFT'}</span></div><pre>{toml}</pre><div className="draft-controls"><label><span>DRAFT NAME</span><input value={draftName} onChange={event => { setDraftName(event.target.value); setDraftMessage('Draft changed; resolve it again before saving.'); }} spellCheck={false} /></label><div><button onClick={() => void resolveDraft()} disabled={factory.busyAction !== null || !plannedRecipeRows.length}>{factory.busyAction === 'plan-draft-resolve' ? 'Resolving…' : 'Resolve against authority'}</button><button className="primary" onClick={() => void saveDraft()} disabled={factory.busyAction !== null || !draftIsCurrent}>{factory.busyAction === 'plan-draft-save' ? 'Saving…' : savedAuthorityDraft || savedDraftSha256 ? 'Save validated update' : 'Save validated draft'}</button></div><p className={draftIsCurrent ? 'valid' : ''}>{draftResult && !draftIsCurrent ? 'Draft changed; resolve it again before saving.' : draftMessage}</p></div><div className="toml-footer"><span>Only catalog identities are accepted; saving does not enqueue or execute the plan</span><code>{savedAuthorityDraft?.path ?? 'plans/drafts/&lt;name&gt;.toml'}</code></div></section>}
        </aside>
      </div>}</details>
    </div>
  );
}

function CohortValidationLifecyclePanel({ lifecycle }: { lifecycle: CohortValidationLifecycle }) {
  const active = lifecycle.active_cohort;
  const performance = lifecycle.performance;
  return <section className="panel cohort-lifecycle-panel">
    <header><div><span>INTEGRATED VALIDATION</span><h3>{lifecycle.label}</h3></div><span className="operational-state blocked">PLANNED · DISARMED</span></header>
    <div className="cohort-lifecycle-facts">
      <article><span>SCIENTIFIC BLOCK</span><strong>10 libraries</strong><small>short scheduler blocks may resume</small></article>
      <article><span>GHIDRA / COHORT</span><strong>{lifecycle.summary.legacy_analyses_per_full_cohort} → {lifecycle.summary.fused_analyses_per_full_cohort}</strong><small>{lifecycle.summary.fused_analyses_per_full_cohort} duplicate analyses avoided</small></article>
      <article><span>PROJECTED CYCLE</span><strong>{performance.projected_fused_cycle_wall_hours_lower.toFixed(1)}–{performance.projected_fused_cycle_wall_hours_upper.toFixed(1)} h</strong><small>{performance.estimate_class.replaceAll('-', ' ')}</small></article>
      <article><span>COMPARISONS</span><strong>50/50 + corpus</strong><small>fold matrix · incremental noise view</small></article>
      <article><span>ADMISSION</span><strong>Manual review</strong><small>validation + discrimination + retention</small></article>
      <article><span>C80 PROGRAMME</span><strong>{lifecycle.summary.programme_cohorts} cohorts</strong><small>{lifecycle.summary.planned_validation_composites.toLocaleString()} validation composites</small></article>
    </div>
    <div className="cohort-lifecycle-chain">
      {lifecycle.stages.map((stage, index) => <Fragment key={stage.id}><span><b>{String(index + 1).padStart(2, '0')}</b><strong>{stage.label}</strong></span>{index < lifecycle.stages.length - 1 && <i>→</i>}</Fragment>)}
    </div>
    {active && <div className="cohort-lifecycle-active"><span>CURRENT RETROFIT</span><strong>{active.id}</strong><small>{active.libraries} libraries</small><em>WIDTH {active.width_state.replaceAll('-', ' ')}</em><em>VALIDATION {active.validation_state.replaceAll('-', ' ')}</em><em>ADMISSION {active.admission_state.replaceAll('-', ' ')}</em></div>}
    <div className="cohort-lifecycle-bound">
      {lifecycle.bound_cohorts.map(cohort => <article key={cohort.id}><b>{String(cohort.order).padStart(2, '0')}</b><p><strong>{cohort.id}</strong><small>{cohort.source_ids.join(' · ')}</small></p><span>{cohort.width_batch_state.replaceAll('-', ' ')}</span><span>{cohort.validation_state.replaceAll('-', ' ')}</span><em>AUTO MATERIALIZE + SCHEDULE</em></article>)}
    </div>
    <footer><code>{lifecycle.authority_path}</code><span>{lifecycle.query_evidence_contract} · routine Ghidra backfill {lifecycle.fusion.routine_backfill}</span></footer>
  </section>;
}

function CampaignProgrammePanel({ programme, lifecycle }: { programme: CampaignProgramme; lifecycle?: CohortValidationProgramme }) {
  const summary = programme.summary;
  const stageLabel = (stage: string) => stage.replaceAll('-', ' ').toUpperCase();
  const stageTone = (stage: string) => stage === 'queue-candidate'
    ? 'ready'
    : stage === 'candidate-screen'
      ? 'cold'
      : 'warning';
  const funnel = [
    ['Research frontier', summary.candidate_population, 'published candidates'],
    ['Source resolved', summary.research_source_pinned_candidates, 'registry-locked archives'],
    ['Archive cached', summary.research_source_cached_candidates, 'receipt-verified bytes'],
    ['C screen', summary.screened_candidates, 'accepted subjects'],
    ['Build source', summary.source_cached_candidates, 'promoted archives'],
    ['Recipe', summary.recipe_ready_candidates, 'reviewed adapters'],
    ['Qualification', summary.qualification_satisfied_candidates, 'sealed subjects'],
  ] as const;
  return <section className="panel c80-programme-panel">
    <div className="c80-programme-head"><div><span>C80 PROGRAMME · FOUR-SOURCE N80</span><h3>{programme.label}</h3></div><div><strong>{programme.candidate_cumulative_proxy_pct.toFixed(6)}%</strong><small>cumulative popularity proxy</small></div><div><strong>{summary.cohorts}</strong><small>10-wide cohorts · final {summary.final_cohort_size}</small></div><div><strong>{summary.planned_campaign_executions.toLocaleString()}</strong><small>planned width executions</small></div><span className="operational-state blocked">RESEARCH PROXY · DISARMED</span></div>
    <div className="c80-funnel" aria-label="C80 planning funnel">
      {funnel.map(([label, value, detail], index) => <Fragment key={label}><article><span>{label}</span><strong>{value.toLocaleString()}<small> / {summary.candidate_population}</small></strong><em>{detail}</em></article>{index < funnel.length - 1 && <i>→</i>}</Fragment>)}
    </div>
    <div className="c80-workload-strip"><span><b>{programme.route_profiles_per_library}</b> routes</span><span><b>{programme.treatments_per_route}</b> treatments</span><span><b>{programme.campaign_executions_per_library}</b> cells / accepted library</span><span><b>{programme.qualification_routes_per_library}</b> qualification edges / library</span><span><b>{summary.planned_qualification_cells.toLocaleString()}</b> maximum qualification cells</span></div>
    <div className="c80-cohort-ledger">
      <header><span>Cohort / research ranks</span><span>Research archive</span><span>Screened</span><span>Build source</span><span>Recipes</span><span>Qualification</span><span>Validation</span><span>Admission</span><span>Current gate</span><span></span></header>
      {programme.cohorts.map(cohort => {
        const lifecycleCohort = lifecycle?.cohorts.find(row => row.id === cohort.id);
        const validationStage = lifecycleCohort?.stages.find(stage => stage.id === 'validation-composites');
        const admissionStage = lifecycleCohort?.stages.find(stage => stage.id === 'corpus-admission');
        return <details key={cohort.id}>
          <summary><div><strong>{String(cohort.order).padStart(2, '0')} · {cohort.id}</strong><small>ranks {cohort.candidate_rank_start}–{cohort.candidate_rank_end} · {cohort.candidates.slice(0, 3).map(row => row.display_name).join(', ')}{cohort.capacity > 3 ? '…' : ''}</small></div><b>{cohort.counts.research_source_pinned}/{cohort.counts.research_source_cached}</b><b>{cohort.counts.screened}/{cohort.capacity}</b><b>{cohort.counts.source_pinned}/{cohort.counts.source_cached}</b><b>{cohort.counts.recipe_ready}/{cohort.capacity}</b><b>{cohort.counts.qualification_satisfied}/{cohort.capacity}</b><b className="lifecycle-state">{validationStage?.state.replaceAll('-', ' ') ?? 'unbound'}</b><b className="lifecycle-state">{admissionStage?.state.replaceAll('-', ' ') ?? 'unbound'}</b><span className={`evidence-badge ${stageTone(cohort.stage)}`}>{stageLabel(cohort.stage)}</span><em>EXPAND</em></summary>
          <section>{lifecycleCohort && <div className="c80-validation-chain">{lifecycleCohort.stages.slice(2).map(stage => <span key={stage.id}><strong>{stage.label}</strong><small>{stage.state.replaceAll('-', ' ')} · {stage.detail}</small></span>)}</div>}<header><span>Rank / candidate</span><span>Research archive</span><span>C screen</span><span>Build source</span><span>Recipe</span><span>Qualification</span><span>Next gate</span></header>{cohort.candidates.map(candidate => <article key={candidate.rank}><div><b>#{candidate.rank} {candidate.display_name}</b><small>{candidate.subject_id !== candidate.canonical_key ? `${candidate.canonical_key} → ${candidate.subject_id}` : candidate.canonical_key}</small></div><span className={candidate.research_source_cached ? 'pass' : 'pending'}>{candidate.research_source_cached ? 'CACHED' : candidate.research_source_pinned ? 'PINNED' : 'UNRESOLVED'}<br /><small>{candidate.research_source_resolver ?? candidate.research_source_reason}</small></span><span className={candidate.screened ? 'pass' : 'pending'}>{candidate.screened ? 'SCREENED' : 'REQUIRED'}</span><span className={candidate.source_cached ? 'pass' : 'pending'}>{candidate.source_cached ? 'VERIFIED' : candidate.source_pinned ? 'PINNED' : 'NOT PROMOTED'}</span><span className={candidate.recipe_ready ? 'pass' : 'pending'}>{candidate.recipe_ready ? 'REVIEWED' : 'REQUIRED'}</span><span className={candidate.qualification_satisfied ? 'pass' : 'pending'}>{candidate.qualification_satisfied ? candidate.qualification_state.toUpperCase() : candidate.width_batch_bound ? candidate.qualification_state.toUpperCase() : 'NOT DEFINED'}</span><strong>{stageLabel(candidate.stage)}</strong></article>)}</section>
        </details>;
      })}
    </div>
    <footer><code>{programme.authorities.source_lock}</code><span>Research archive cache ≠ accepted C-library cohort. Screening, recipe review and qualification remain independent gates.</span></footer>
  </section>;
}

export function QualificationPipelinePanel({ factory }: { factory: FactoryApiState }) {
  const pipeline = factory.authority?.qualification_pipeline;
  if (!pipeline) return null;
  return <section className="panel qualification-pipeline-panel">
    <div className="panel-header"><h3>Campaign qualification pipeline</h3><span className={`evidence-badge ${pipeline.summary.blocked ? 'warning' : 'ready'}`}>{pipeline.state.toUpperCase()} · {pipeline.summary.satisfied}/{pipeline.summary.batches} GATES</span></div>
    <div className="qualification-chain" aria-label="Campaign qualification stages"><span><b>01</b><strong>Resolve</strong><small>all exact cells</small></span><i>→</i><span><b>02</b><strong>Compile qualify</strong><small>target + generation edges</small></span><i>→</i><span><b>03</b><strong>Seal</strong><small>input-bound evidence</small></span><i>→</i><span><b>04</b><strong>Build queue</strong><small>short chunks, disarmed</small></span><i>→</i><span><b>05</b><strong>Full-path canary</strong><small>compile + Ghidra + publish</small></span><i>→</i><span><b>06</b><strong>Admit</strong><small>explicit operator arm</small></span></div>
    <div className="qualification-gate-ledger">
      <header><span>Width batch</span><span>Compilation coverage</span><span>Authority / evidence</span><span>Promotion</span></header>
      {pipeline.gates.map(gate => <article key={gate.batch_id}><div><strong>{gate.batch_id}</strong><small>{gate.state.replaceAll('-', ' ')}</small></div><div><strong>{gate.summary.total ? `${gate.summary.built}/${gate.summary.total}` : 'legacy'}</strong><small>{gate.summary.failed} failed · {gate.summary.remaining} remaining</small></div><div><code>{gate.authority_path ?? 'historical digest exemption'}</code><small>{gate.evidence_path ?? gate.reason ?? 'no qualification evidence'}</small></div><span className={`evidence-badge ${gate.satisfied ? 'ready' : 'warning'}`}>{gate.satisfied ? gate.promotion_state.replaceAll('-', ' ') : 'blocked'}</span></article>)}
    </div>
    <footer><code>fidb-poc qualification status --project-root .</code><span>Passing qualification unlocks the auto-batch queue builder; the generated campaign remains disarmed until the canary and explicit operator admission.</span></footer>
  </section>;
}

export function TimeBlockPlanPanel({ factory }: { factory: FactoryApiState }) {
  const plan = factory.authority?.time_block_plan;
  if (!plan) return null;
  const materialized = factory.authority?.materialized_campaigns.find(campaign => campaign.id === plan.id);
  const materializedBlocks = new Map(materialized?.blocks.map(block => [block.id, block]));
  const schedule = factory.preflight?.policy.schedule;
  const start = typeof schedule?.start === 'string' ? schedule.start : plan.blocks[0]?.expected_start_local ?? '01:00';
  const stop = typeof schedule?.stop_claiming === 'string' ? schedule.stop_claiming : '05:30';
  const finishStarted = schedule?.finish_started_batch === true;
  const chainBatches = schedule?.chain_batches === true;
  const active = factory.snapshot?.execution_block;
  const materializedReady = materialized?.readiness.ready === true;
  const candidate = factory.authority?.auto_batch_campaigns[0];
  return <section className="panel time-block-panel">
    <div className="panel-header"><h3>Time-aware campaign · {plan.label}</h3><span className="authority-badge">{materializedReady ? materialized?.state.replaceAll('-', ' ').toUpperCase() : 'DRAFT · DISARMED'}</span></div>
    <div className="time-block-summary">
      <article><span>NOMINAL WALL TIME</span><strong>{plan.summary.estimated_hours.toFixed(1)} h</strong><small>{plan.summary.planning_lower_hours.toFixed(1)}–{plan.summary.planning_upper_hours.toFixed(1)} h planning range</small></article>
      <article><span>BLOCKS</span><strong>{plan.summary.blocks}</strong><small>target {plan.policy.target_block_hours.toFixed(1)} h · hard planning ceiling {plan.policy.max_block_hours.toFixed(0)} h</small></article>
      <article><span>EXACT WIDTH</span><strong>{plan.summary.executions.toLocaleString()}</strong><small>{plan.summary.android_executions.toLocaleString()} Android executions included</small></article>
      <article><span>MEASURED BASIS</span><strong>{plan.reference.estimated_cells_per_wall_hour.toFixed(1)} cells/h</strong><small>{plan.performance_profile.label} · {plan.reference.case_id}</small></article>
    </div>
    <div className="time-block-schedule"><div><span>AUTOMATIC ADMISSION</span><strong>{start}–{stop} · Europe/Luxembourg</strong><small>{chainBatches ? 'Drained chunks chain while the window remains open.' : 'At most one ordered block starts per window.'} {finishStarted ? 'A started block drains completely after the window closes.' : 'Finish-started policy is not active.'}</small></div><div><span>CURRENT ADMISSION</span><strong>{active?.active ? active.batch_id : 'No block active'}</strong><small>{active?.active ? `${active.remaining ?? '—'} jobs remain · ${active.admission_id}` : 'No block is currently admitted'}</small></div><div><span>MANUAL TIMER BYPASS</span><code>fidb-poc queue start-block --project-root .</code><small>Requires an armed queue; admits one block but executes nothing itself.</small></div></div>
    {candidate && <>
      <div className="time-block-summary">
        <article><span>AUTO-BUILT CHUNKS</span><strong>{candidate.summary.chunks}</strong><small>{candidate.policy.target_minutes} min target · {candidate.policy.max_minutes} min central ceiling</small></article>
        <article><span>EXACT PARTITION</span><strong>{candidate.summary.executions.toLocaleString()}</strong><small>{candidate.summary.route_bundles} library/route bundles · all treatments kept together</small></article>
        <article><span>MANUAL FIT</span><strong>{Math.max(...candidate.chunks.map(chunk => chunk.planning_upper_minutes)).toFixed(0)} min</strong><small>worst +{Math.round(candidate.policy.uncertainty_fraction * 100)}% planning bound · final tail {candidate.chunks.at(-1)?.estimated_minutes.toFixed(0)} min</small></article>
        <article><span>CANDIDATE QUEUE</span><strong>{candidate.queue_integrity.replaceAll('-', ' ')}</strong><small>{candidate.queue} · never substituted into the live ledger</small></article>
      </div>
      <div className="time-block-ledger">
        <header><span>Candidate chunk</span><span>Libraries</span><span>Width</span><span>Estimate / range</span><span>State</span></header>
        {candidate.chunks.map(chunk => <article key={chunk.id}><div><strong>#{String(chunk.position).padStart(3, '0')}</strong><small>{chunk.id}</small></div><div><strong>{chunk.source_ids.join(' + ')}</strong><small>{chunk.plan}</small></div><div><strong>{chunk.executions.toLocaleString()} executions</strong><small>{chunk.route_ids.length} route bundles · all treatments</small></div><div><strong>{chunk.estimated_minutes.toFixed(1)} min</strong><small>{chunk.planning_lower_minutes.toFixed(1)}–{chunk.planning_upper_minutes.toFixed(1)} min</small></div><span className={`evidence-badge ${chunk.plan_integrity === 'verified' && chunk.queue_registered ? 'ready' : 'cold'}`}>{chunk.plan_integrity} · {chunk.queue_registered ? 'registered' : 'drifted'}</span></article>)}
      </div>
    </>}
    <div className="time-block-ledger">
      <header><span>Block / nominal window</span><span>Libraries</span><span>Width</span><span>Estimate / range</span><span>State</span></header>
      {plan.blocks.map(block => {
        const frozen = materializedBlocks.get(block.id);
        return <article key={block.id}><div><strong>#{String(block.position).padStart(2, '0')} · {start} → {block.expected_nominal_end_local}</strong><small>{block.id}</small></div><div><strong>{block.items.map(item => item.label).join(' + ')}</strong><small>{block.items.map(item => `${item.source_id}@${item.version}`).join(' · ')}</small></div><div><strong>{block.executions.toLocaleString()} executions</strong><small>{block.android_executions.toLocaleString()} Android · exact applicability</small></div><div><strong>{block.estimated_hours.toFixed(2)} h</strong><small>{block.planning_lower_hours.toFixed(2)}–{block.planning_upper_hours.toFixed(2)} h · ±{Math.round(plan.policy.uncertainty_fraction * 100)}%</small></div><span className={`evidence-badge ${frozen?.plan_integrity === 'verified' && frozen.queue_registered ? 'ready' : 'cold'}`}>{frozen ? `${frozen.plan_integrity} · ${frozen.queue_registered ? 'queued' : 'unregistered'}` : block.state.replaceAll('-', ' ')}</span></article>;
      })}
    </div>
    <footer className="time-block-note"><strong>{materializedReady ? 'Frozen cells, disarmed execution.' : 'Dynamic draft, stable execution.'}</strong><span>{materializedReady ? 'All five generated plans match their file pins and ordered queue-cell digests. The queue is registered but remains disarmed pending explicit operator review.' : 'Factor, compiler, route, treatment, source-size or performance-profile changes automatically update this projection. Materialization must freeze the block membership and plan digest first, so an armed campaign can never reshape itself silently.'}</span><code>{materialized?.materialization_digest ?? plan.plan_digest}</code></footer>
  </section>;
}
