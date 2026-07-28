/**
 * Runtime-agnostic API router.
 *
 * Takes a standard `Request`, returns a standard `Response`. The Cloudflare
 * Pages Function and the Node server are both thin adapters over this, so the
 * two deployments cannot drift apart.
 */

import { lookupIp } from './lookups/ip.js';
import { lookupDomain } from './lookups/domain.js';
import { lookupPhone } from './lookups/phone.js';
import { ValidationError } from './lib/validate.js';

export const API_VERSION = '1.0.0';

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { ...JSON_HEADERS, ...extra },
  });
}

/**
 * Handle one API request.
 *
 * @param {Request} request
 * @param {{env?: object, loadData?: (path: string) => Promise<any>, basePath?: string}} context
 */
export async function handleApiRequest(request, context = {}) {
  const { env = {}, loadData, basePath = '/api' } = context;
  const url = new URL(request.url);

  // Same-origin by default; the API is a proxy and has no business being
  // callable from arbitrary pages.
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { allow: 'GET, POST, OPTIONS' } });
  }
  if (request.method !== 'GET' && request.method !== 'POST') {
    return json({ error: 'Method not allowed', detail: 'Use GET or POST.' }, 405, { allow: 'GET, POST, OPTIONS' });
  }

  const route = url.pathname.slice(basePath.length).replace(/^\/+|\/+$/g, '');
  const params = await readParams(request, url);
  const started = Date.now();

  try {
    let result;
    switch (route) {
      case 'health':
        return json({ status: 'ok', version: API_VERSION, time: new Date().toISOString() });

      case 'ip':
        result = await lookupIp(required(params, 'q', 'an IP address'), env);
        break;

      case 'domain':
        result = await lookupDomain(required(params, 'q', 'a domain name'), env);
        break;

      case 'phone':
        result = await lookupPhone(required(params, 'q', 'a phone number'), params.region, loadData, env);
        break;

      case '':
        return json({
          service: 'GhostTrace API',
          version: API_VERSION,
          endpoints: {
            'GET /api/ip?q=<address>': 'Geolocation, RDAP registry, reverse DNS and exposure for an IPv4/IPv6 address.',
            'GET /api/domain?q=<domain>': 'RDAP registration, DNS, email authentication, Certificate Transparency and HTTP headers.',
            'GET /api/phone?q=<number>&region=<ISO2>': 'Validation, line type, allocation area, carrier and timezones.',
            'GET /api/health': 'Liveness probe.',
          },
        });

      default:
        return json({ error: 'Not found', detail: `No endpoint at /${route}.` }, 404);
    }

    return json({ ...result, elapsedMs: Date.now() - started });
  } catch (err) {
    if (err instanceof ValidationError) {
      return json({ error: 'Invalid input', detail: err.message }, 400);
    }
    // Upstream failures inside a lookup are captured per-source by `gather`;
    // reaching here means something structural broke.
    return json(
      { error: 'Lookup failed', detail: err?.message ?? 'Unknown error', elapsedMs: Date.now() - started },
      502,
    );
  }
}

/** Merge query-string and JSON-body parameters. */
async function readParams(request, url) {
  const params = Object.fromEntries(url.searchParams);
  if (request.method === 'POST') {
    try {
      const body = await request.json();
      if (body && typeof body === 'object') Object.assign(params, body);
    } catch {
      // A malformed body just leaves the query-string params in place.
    }
  }
  return params;
}

function required(params, key, description) {
  const value = params[key];
  if (value == null || String(value).trim() === '') {
    throw new ValidationError(`Missing "${key}" parameter — supply ${description}.`);
  }
  return String(value);
}
