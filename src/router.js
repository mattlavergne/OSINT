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
import { lookupEmail } from './lookups/email.js';
import { lookupUsername } from './lookups/username.js';
import { lookupAsn } from './lookups/asn.js';
import { ValidationError } from './lib/validate.js';

export const API_VERSION = '2.0.0';

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
  const options = { depth: readDepth(params) };

  try {
    let result;
    switch (route) {
      case 'health':
        return json({ status: 'ok', version: API_VERSION, time: new Date().toISOString() });

      case 'ip':
        result = await lookupIp(required(params, 'q', 'an IP address'), env, options);
        break;

      case 'domain':
        result = await lookupDomain(required(params, 'q', 'a domain name'), env, options);
        break;

      case 'phone':
        result = await lookupPhone(required(params, 'q', 'a phone number'), params.region, loadData, env, options);
        break;

      case 'email':
        result = await lookupEmail(required(params, 'q', 'an email address'), env, options);
        break;

      case 'username':
        result = await lookupUsername(required(params, 'q', 'a username'), env, options);
        break;

      case 'asn':
        result = await lookupAsn(required(params, 'q', 'an AS number'), env, options);
        break;

      case '':
        return json({
          service: 'GhostTrace API',
          version: API_VERSION,
          endpoints: {
            'GET /api/ip?q=<address>': 'Geolocation consensus, RDAP registry, geofeed, BGP routing, blocklists, Tor status and exposure for an IPv4/IPv6 address.',
            'GET /api/domain?q=<domain>': 'RDAP registration, DNS, email authentication, DKIM selectors, Certificate Transparency, technology fingerprint, favicon hash and subdomain mapping.',
            'GET /api/phone?q=<number>&region=<ISO2>': 'Validation, line type, NANP rate centre and switch, carrier, timezones and business attribution.',
            'GET /api/email?q=<address>': 'Gravatar profile, linked accounts, mail posture, domain age and address classification.',
            'GET /api/username?q=<handle>': 'Account discovery across platforms with real existence APIs, cross-correlated into one identity view.',
            'GET /api/asn?q=<AS number>': 'Registry record, announced prefixes, upstreams, peers, exchange presence and abuse contacts.',
            'GET /api/health': 'Liveness probe.',
          },
          parameters: {
            depth: 'standard (default) or deep. Deep unlocks DKIM and SRV enumeration, subdomain resolution, '
              + 'takeover detection, ASN registry data and routing history. It costs substantially more upstream '
              + 'requests — see the README note on the Cloudflare Workers 50-subrequest limit on the free plan.',
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

/**
 * Read the scan depth.
 *
 * The two modes exist because of a hard platform limit rather than a taste
 * preference: a Cloudflare Worker on the free plan may make 50 subrequests per
 * request, and a full domain report already sits close to that. `standard` is
 * built to fit inside it; `deep` turns on the enumeration passes — DKIM
 * selectors, SRV services, subdomain resolution, routing history — that are
 * individually cheap but collectively push a lookup well past the ceiling.
 *
 * An unrecognised value is treated as `standard` rather than rejected, so a
 * typo degrades to a working lookup instead of a 400.
 */
function readDepth(params) {
  return String(params.depth ?? '').toLowerCase() === 'deep' ? 'deep' : 'standard';
}

function required(params, key, description) {
  const value = params[key];
  if (value == null || String(value).trim() === '') {
    throw new ValidationError(`Missing "${key}" parameter — supply ${description}.`);
  }
  return String(value);
}
