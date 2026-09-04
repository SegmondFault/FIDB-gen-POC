import type { NextRequest } from 'next/server';

export const dynamic = 'force-dynamic';

const readRoutes = new Set([
  'health',
  'status',
  'snapshot',
  'events',
  'timings',
  'capabilities',
  'authority',
  'lane-inventory',
  'ecological-validation',
  'hash-discrimination',
  'noisy-hashes',
  'retention',
  'preflight',
]);
const writeRoutes = new Set([
  'sync',
  'pause',
  'resume',
  'plan-drafts/resolve',
  'plan-drafts/save',
  'ecological-validation/import',
  'ecological-validation/run',
  'noisy-hashes/decision',
  'retention/plan',
  'retention/apply',
]);
const maxRequestBytes = 64 * 1024;
const maxImportBytes = 512 * 1024 * 1024;
const maxResponseBytes = 2 * 1024 * 1024;

type RouteContext = {
  params: Promise<{ path: string[] }>;
};

function jsonError(status: number, code: string, message: string) {
  return Response.json(
    { error: { code, message } },
    { status, headers: { 'Cache-Control': 'no-store' } },
  );
}

function apiOrigin(): URL {
  const value = process.env.FIDB_API_ORIGIN ?? 'http://127.0.0.1:8765';
  const origin = new URL(value);
  const loopback = new Set(['127.0.0.1', 'localhost', '[::1]']);
  if (
    origin.protocol !== 'http:' ||
    !loopback.has(origin.hostname) ||
    origin.username ||
    origin.password ||
    (origin.pathname !== '/' && origin.pathname !== '') ||
    origin.search ||
    origin.hash
  ) {
    throw new Error('FIDB_API_ORIGIN must be a plain loopback HTTP origin');
  }
  return origin;
}

function mutationIsSameOrigin(request: NextRequest) {
  const origin = request.headers.get('origin');
  return origin !== null && origin === new URL(request.url).origin;
}

function validatedQuery(endpoint: string, requestUrl: URL) {
  const allowed = endpoint === 'events'
    ? new Set(['after', 'limit'])
    : endpoint === 'timings'
      ? new Set(['limit'])
      : endpoint === 'snapshot'
        ? new Set(['detail', 'include_inactive'])
      : new Set<string>();
  for (const key of requestUrl.searchParams.keys()) {
    if (!allowed.has(key)) return null;
  }
  return requestUrl.search;
}

async function proxy(
  request: NextRequest,
  context: RouteContext,
  method: 'GET' | 'POST',
) {
  const { path } = await context.params;
  if (!Array.isArray(path) || path.length < 1 || path.length > 2) {
    return jsonError(404, 'route_not_found', 'Unknown coordinator API route');
  }
  const endpoint = path.join('/');
  const allowed = method === 'GET' ? readRoutes : writeRoutes;
  if (!allowed.has(endpoint)) {
    return jsonError(404, 'route_not_found', 'Unknown coordinator API route');
  }
  if (method === 'POST' && !mutationIsSameOrigin(request)) {
    return jsonError(403, 'origin_rejected', 'Mutation requires the control-panel origin');
  }

  const requestUrl = new URL(request.url);
  const query = validatedQuery(endpoint, requestUrl);
  if (query === null) {
    return jsonError(400, 'invalid_query', 'Unsupported query parameter');
  }

  const isImport = endpoint === 'ecological-validation/import';
  let body: BodyInit | null | undefined;
  if (method === 'POST') {
    if (isImport) {
      const rawLength = request.headers.get('content-length');
      const length = rawLength === null ? NaN : Number(rawLength);
      if (!Number.isSafeInteger(length) || length < 1) {
        return jsonError(411, 'content_length_required', 'Import requires a positive Content-Length');
      }
      if (length > maxImportBytes) {
        return jsonError(413, 'request_too_large', 'Ecological import exceeds 512 MiB');
      }
      body = request.body;
    } else {
      const buffered = await request.arrayBuffer();
      if (buffered.byteLength > maxRequestBytes) {
        return jsonError(413, 'request_too_large', 'Coordinator request is too large');
      }
      body = buffered;
    }
  }

  let upstream: Response;
  try {
    const origin = apiOrigin();
    const target = new URL(`/api/v1/${endpoint}${query}`, origin);
    const headers = new Headers({ Accept: 'application/json' });
    if (method === 'POST') {
      headers.set('Content-Type', isImport ? 'application/octet-stream' : 'application/json');
    }
    if (isImport) {
      for (const name of [
        'x-fidb-filename',
        'x-fidb-label',
        'x-fidb-platform-hint',
        'x-fidb-expected-present',
        'x-fidb-expected-absent',
        'x-fidb-truth-complete',
      ]) {
        const value = request.headers.get(name);
        if (value !== null) headers.set(name, value);
      }
      const length = request.headers.get('content-length');
      if (length !== null) headers.set('content-length', length);
    }
    const init: RequestInit & { duplex?: 'half' } = {
      method,
      headers,
      body,
      cache: 'no-store',
      redirect: 'manual',
    };
    if (isImport) init.duplex = 'half';
    upstream = await fetch(target, init);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Coordinator API unavailable';
    return jsonError(502, 'coordinator_unavailable', message);
  }

  if (upstream.status >= 300 && upstream.status < 400) {
    return jsonError(502, 'coordinator_redirect_rejected', 'Coordinator redirects are not allowed');
  }

  const payload = await upstream.arrayBuffer();
  if (payload.byteLength > maxResponseBytes) {
    return jsonError(502, 'response_too_large', 'Coordinator response exceeded the proxy limit');
  }
  return new Response(payload, {
    status: upstream.status,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': upstream.headers.get('content-type') ?? 'application/json',
    },
  });
}

export function GET(request: NextRequest, context: RouteContext) {
  return proxy(request, context, 'GET');
}

export function POST(request: NextRequest, context: RouteContext) {
  return proxy(request, context, 'POST');
}
