/**
 * RDAP client and vCard flattener.
 *
 * RDAP is the IETF replacement for port-43 WHOIS: same registry data, but as
 * structured JSON over HTTPS with a documented bootstrap. That makes it the
 * right primitive for a Workers-hosted tool — no WHOIS socket, no scraping,
 * no per-registrar text formats to reverse-engineer.
 */

import { getJson } from './http.js';

const BOOTSTRAP = 'https://rdap.org';

/** Fetch an RDAP object. `kind` is "domain" or "ip". */
export async function lookup(kind, target) {
  return getJson(`${BOOTSTRAP}/${kind}/${encodeURIComponent(target)}`, {
    source: 'rdap.org',
    accept: 'application/rdap+json, application/json',
    timeout: 10000,
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
