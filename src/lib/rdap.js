/**
 * RDAP client and vCard flattener.
 *
 * RDAP is the IETF replacement for port-43 WHOIS: same registry data, but as
 * structured JSON over HTTPS with a documented bootstrap. That makes it the
 * right primitive for a Workers-hosted tool — no WHOIS socket, no scraping,
 * no per-registrar text formats to reverse-engineer.
 */

import { getJson } from './http.js';
import { expandIpv6 } from './dns.js';

/**
 * IANA's official bootstrap registries map an address range or TLD to the
 * authoritative RDAP server. Going through them means one fewer third party in
 * the path: rdap.org is a convenience redirector, it sits behind Cloudflare,
 * and Worker-to-Cloudflare requests to it have been returning 525 (upstream TLS
 * handshake failure). It stays on as a fallback, not the primary route.
 */
const IANA_BOOTSTRAP = {
  ip: 'https://data.iana.org/rdap/ipv4.json',
  ip6: 'https://data.iana.org/rdap/ipv6.json',
  domain: 'https://data.iana.org/rdap/dns.json',
};

const REDIRECTOR = 'https://rdap.org';

/** Bootstrap files change rarely; hold them for the life of the isolate. */
const bootstrapCache = new Map();

async function bootstrap(name) {
  if (bootstrapCache.has(name)) return bootstrapCache.get(name);

  const promise = getJson(IANA_BOOTSTRAP[name], {
    source: 'data.iana.org',
    timeout: 8000,
    // Small, static and shared by every lookup — worth an edge cache.
    cacheTtl: 86400,
  }).catch((err) => {
    bootstrapCache.delete(name);
    throw err;
  });

  bootstrapCache.set(name, promise);
  return promise;
}

/** IPv4 dotted quad to a 32-bit integer. */
function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8 >>> 0) + Number(octet), 0) >>> 0;
}

/** IPv6 address to a 128-bit BigInt, so prefixes compare exactly. */
function ipv6ToBigInt(ip) {
  return expandIpv6(ip)
    .split(':')
    .reduce((acc, group) => (acc << 16n) + BigInt(parseInt(group, 16) || 0), 0n);
}

/**
 * Does `ip` fall inside `prefix/length`? Exported for tests.
 *
 * IPv6 bootstrap prefixes are routinely shorter than one hextet (2000::/3,
 * 2600::/12), so comparing whole hextets is wrong — it matches everything and
 * silently picks an arbitrary registry. Both families mask numerically.
 */
export function inPrefix(ip, prefix, length, isV6) {
  if (isV6) {
    const shift = BigInt(128 - length);
    return (ipv6ToBigInt(ip) >> shift) === (ipv6ToBigInt(prefix) >> shift);
  }
  const mask = length === 0 ? 0 : (0xffffffff << (32 - length)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(prefix) & mask);
}

/** Resolve the authoritative RDAP base URL for an IP via the bootstrap. */
async function baseUrlForIp(ip) {
  const isV6 = ip.includes(':');
  const registry = await bootstrap(isV6 ? 'ip6' : 'ip');

  let best = null;
  for (const [ranges, urls] of registry.services ?? []) {
    for (const range of ranges) {
      const [prefix, lengthText] = range.split('/');
      const length = Number(lengthText);

      const matches = inPrefix(ip, prefix, length, isV6);

      // Longest prefix wins, as the RFC 7484 bootstrap requires.
      if (matches && (!best || length > best.length)) {
        best = { length, url: urls.find((u) => u.startsWith('https:')) ?? urls[0] };
      }
    }
  }
  return best?.url ?? null;
}

/** Resolve the authoritative RDAP base URL for a domain's TLD. */
async function baseUrlForDomain(domain) {
  const tld = domain.split('.').pop().toLowerCase();
  const registry = await bootstrap('domain');

  for (const [tlds, urls] of registry.services ?? []) {
    if (tlds.some((entry) => entry.toLowerCase() === tld)) {
      return urls.find((u) => u.startsWith('https:')) ?? urls[0];
    }
  }
  return null;
}

/**
 * Fetch an RDAP object. `kind` is "domain" or "ip".
 *
 * Tries the authoritative server named by IANA first, then falls back to the
 * rdap.org redirector so a bootstrap outage does not take the panel down.
 */
export async function lookup(kind, target) {
  const options = {
    accept: 'application/rdap+json, application/json',
    timeout: 10000,
  };

  let base = null;
  try {
    base = kind === 'ip' ? await baseUrlForIp(target) : await baseUrlForDomain(target);
  } catch {
    // Bootstrap unavailable — fall through to the redirector.
  }

  if (base) {
    try {
      const url = `${base.replace(/\/$/, '')}/${kind}/${encodeURIComponent(target)}`;
      return await getJson(url, { ...options, source: new URL(base).hostname });
    } catch {
      // Authoritative server refused or is down; try the redirector.
    }
  }

  return getJson(`${REDIRECTOR}/${kind}/${encodeURIComponent(target)}`, {
    ...options,
    source: 'rdap.org',
  });
}

/**
 * Flatten an RDAP jCard (`vcardArray`) into a plain object.
 * Registrars redact most fields under GDPR, so absent values are normal.
 */
export function parseVcard(vcardArray) {
  if (!Array.isArray(vcardArray) || vcardArray[0] !== 'vcard') return {};
  const out = {};

  for (const entry of vcardArray[1] ?? []) {
    const [field, , , value] = entry;
    if (value == null || value === '') continue;

    switch (field) {
      case 'fn': out.name = value; break;
      case 'org': out.organization = Array.isArray(value) ? value.join(' ') : value; break;
      case 'email': out.email = value; break;
      case 'tel': out.phone = String(value).replace(/^tel:/, ''); break;
      case 'adr': {
        const parts = (Array.isArray(value) ? value : [value]).filter(Boolean);
        if (parts.length) out.address = parts.join(', ');
        break;
      }
      case 'kind': out.kind = value; break;
      default: break;
    }
  }
  return out;
}

/**
 * Collect RDAP entities by role, flattening nested entities (registrars often
 * nest abuse contacts one level down).
 */
export function entitiesByRole(entities = [], depth = 0) {
  const found = {};
  if (depth > 3) return found;

  for (const entity of entities) {
    const card = parseVcard(entity.vcardArray);
    const record = {
      handle: entity.handle ?? null,
      ...card,
    };

    for (const role of entity.roles ?? []) {
      // Keep the first, most specific match for each role.
      if (!found[role]) found[role] = record;
    }

    if (entity.entities?.length) {
      const nested = entitiesByRole(entity.entities, depth + 1);
      for (const [role, value] of Object.entries(nested)) {
        if (!found[role]) found[role] = value;
      }
    }
  }
  return found;
}

/** Pull the named event date out of an RDAP `events` array. */
export function eventDate(events = [], action) {
  const match = events.find((e) => e.eventAction === action);
  return match?.eventDate ?? null;
}

/** Normalize EPP status codes into something a human can skim. */
export function describeStatus(status = []) {
  const notes = {
    'client transfer prohibited': 'Registrar lock is on — the domain cannot be transferred away.',
    'client delete prohibited': 'Registrar lock prevents deletion.',
    'client update prohibited': 'Registrar lock prevents record updates.',
    'server transfer prohibited': 'Registry-level transfer lock.',
    'client hold': 'Registrar has withdrawn the domain from DNS.',
    'server hold': 'Registry has withdrawn the domain from DNS.',
    'pending delete': 'Domain is in the deletion pipeline.',
    'redemption period': 'Domain expired and is in the redemption grace period.',
    'add period': 'Recently registered — still inside the 5-day add grace period.',
    'auto renew period': 'Recently auto-renewed.',
  };
  return status.map((s) => ({ code: s, note: notes[s.toLowerCase()] ?? null }));
}
