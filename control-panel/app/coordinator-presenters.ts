import type { CoordinatorEvent, CoordinatorWorker } from './use-factory-api';

export function eventTone(event: CoordinatorEvent) {
  if (event.event_type.includes('complete') || event.event_type.includes('synced')) return 'success';
  if (event.event_type.includes('fail') || event.event_type.includes('blocked')) return 'warning';
  return 'info';
}

export function eventDetail(event: CoordinatorEvent) {
  const payload = Object.entries(event.payload)
    .slice(0, 3)
    .map(([key, value]) => `${key}=${typeof value === 'string' ? value : JSON.stringify(value)}`)
    .join(' · ');
  return [event.batch_id, event.job_id?.slice(0, 12), payload].filter(Boolean).join(' · ') || event.actor;
}

export function externalWorkerDisplay(worker: CoordinatorWorker) {
  const raw = worker.metadata.external_toolchain;
  const external = raw && typeof raw === 'object' ? raw as Record<string, unknown> : null;
  const rawMetadata = external?.metadata;
  const metadata = rawMetadata && typeof rawMetadata === 'object'
    ? rawMetadata as Record<string, unknown>
    : null;
  const rawDefinition = external?.definition;
  const definition = rawDefinition && typeof rawDefinition === 'object'
    ? rawDefinition as Record<string, unknown>
    : null;
  const languages = Array.isArray(definition?.languages)
    ? definition.languages.filter(value => typeof value === 'string').join(' + ')
    : null;
  const details = metadata
    ? [metadata.hardware, metadata.macos_version, metadata.xcode_version, metadata.sdk_version]
      .filter(value => typeof value === 'string')
      .join(' · ')
    : `${worker.transport} · ${worker.pools.join(', ')}`;
  return {
    details: `${details}${details ? ' · ' : ''}last seen ${new Date(worker.last_seen_at).toLocaleString()}`,
    state: external?.ready === true && languages ? `${languages} ready` : worker.state,
    tone: worker.state === 'online' && (external === null || external.ready === true) ? 'ready' : 'offline',
  };
}

export function eventTime(event: CoordinatorEvent, milliseconds = false) {
  const date = new Date(event.occurred_at);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: milliseconds ? 3 : undefined,
    hour12: false,
  });
}
