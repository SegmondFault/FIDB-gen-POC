import type { ReactNode } from 'react';

import { useFactoryApi, type PanelReadKey } from './use-factory-api';

export type FactoryApiState = ReturnType<typeof useFactoryApi>;

export function PanelReadWarning({
  factory,
  endpoints,
}: {
  factory: FactoryApiState;
  endpoints: PanelReadKey[];
}) {
  const failures = endpoints.flatMap(endpoint => {
    const message = factory.panelErrors[endpoint];
    return message ? [`${endpoint.replaceAll('-', ' ')}: ${message}`] : [];
  });
  return failures.length
    ? <div className="inline-warning" role="status">Panel data is stale: {failures.join(' · ')}</div>
    : null;
}

export function ViewIntro({ title, action }: { kicker: string; title: string; copy?: string; action?: ReactNode }) {
  return <section className="view-intro"><h2>{title}</h2>{action}</section>;
}
