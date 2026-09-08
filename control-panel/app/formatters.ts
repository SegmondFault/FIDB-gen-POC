import type { StageSpan, TimingEta } from './use-factory-api';

export function formatDurationNs(value: number | null | undefined) {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return '—';
  const milliseconds = value / 1_000_000;
  if (milliseconds < 1) return `${Math.round(value / 1_000)} µs`;
  if (milliseconds < 1_000) return `${milliseconds < 10 ? milliseconds.toFixed(1) : Math.round(milliseconds)} ms`;
  const seconds = milliseconds / 1_000;
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} s`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${minutes < 10 ? minutes.toFixed(1) : Math.round(minutes)} min`;
  const hours = minutes / 60;
  return `${hours < 10 ? hours.toFixed(1) : Math.round(hours)} h`;
}

export function formatPlanningDurationNs(value: number | null | undefined) {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return '—';
  const days = value / 86_400_000_000_000;
  if (days < 1) return formatDurationNs(value);
  if (days < 365) return `${days < 10 ? days.toFixed(1) : Math.round(days)} d`;
  const years = days / 365.25;
  return `${years < 10 ? years.toFixed(1) : Math.round(years)} y`;
}

export function elapsedNs(startedAt: string, now: number, endedAt?: string | null) {
  const start = Date.parse(startedAt);
  const end = endedAt ? Date.parse(endedAt) : now;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null;
  return (end - start) * 1_000_000;
}

export function formatStartedAt(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function stageLabel(value: string) {
  return value.replaceAll('-', ' ').replace(/\b\w/g, letter => letter.toUpperCase());
}

export function formatBytes(value: number | null) {
  if (value === null || !Number.isFinite(value) || value < 0) return '—';
  if (value < 1024) return `${Math.round(value)} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
  let amount = value / 1024;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount < 10 ? amount.toFixed(1) : Math.round(amount)} ${units[unit]}`;
}

export function numericMetric(span: StageSpan, key: string) {
  const value = span.metrics?.[key];
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

export function resourceEvidence(span: StageSpan) {
  const cpu = [
    'self_user_cpu_duration_ns',
    'self_system_cpu_duration_ns',
    'child_user_cpu_duration_ns',
    'child_system_cpu_duration_ns',
  ].map(key => numericMetric(span, key)).filter((value): value is number => value !== null)
    .reduce((sum, value) => sum + value, 0);
  const rssValues = [
    numericMetric(span, 'self_max_rss_bytes_peak'),
    numericMetric(span, 'child_max_rss_bytes_peak'),
  ].filter((value): value is number => value !== null);
  const rss = rssValues.length ? Math.max(...rssValues) : null;
  const programs = numericMetric(span, 'program_count') ?? numericMetric(span, 'programs');
  const details = [
    typeof span.metrics?.cache_hit === 'boolean' ? `cache ${span.metrics.cache_hit ? 'hit' : 'miss'}` : null,
    numericMetric(span, 'bytes') !== null ? `${formatBytes(numericMetric(span, 'bytes'))} I/O` : null,
    numericMetric(span, 'object_count') !== null ? `${numericMetric(span, 'object_count')} objects` : null,
    programs !== null ? `${programs} programs` : null,
    numericMetric(span, 'added') !== null ? `${numericMetric(span, 'added')} FID records added` : null,
  ].filter(Boolean);
  return {
    cpu,
    rss,
    details: details.join(' · '),
  };
}

export function etaDuration(eta: TimingEta | null) {
  if (!eta) return null;
  for (const value of [
    eta.remaining_duration_ns,
    eta.p50_remaining_duration_ns,
  ]) {
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
  }
  return null;
}
