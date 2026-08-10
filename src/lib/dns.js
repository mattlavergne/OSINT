/**
 * DNS-over-HTTPS client.
 *
 * Raw UDP sockets are unavailable on Workers (and unreliable behind corporate
 * egress anyway), so all resolution goes over DoH. Cloudflare is primary,
 * Google is the fallback — both speak the same JSON response shape.
 */

import { getJson, SourceError } from './http.js';

const RESOLVERS = [
  { name: 'cloudflare-dns.com', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'dns.google', url: 'https://dns.google/resolve' },
];

/** DNS RCODEs worth surfacing distinctly to the user. */
const RCODE = { 0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };

/**
 * Resolve a single record type.
 *
 * @param {string} name  fully-qualified name (already validated)
 * @param {string} type  A, AAAA, MX, NS, TXT, SOA, CAA, PTR, ...
 * @returns {Promise<{type: string, status: string, records: string[], ttl: number|null}>}
 */
export async function resolve(name, type) {
  let lastError;

  for (const resolver of RESOLVERS) {
    const url = `${resolver.url}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    try {
      const body = await getJson(url, {
        source: resolver.name,
        accept: 'application/dns-json',
        headers: { accept: 'application/dns-json' },
        timeout: 6000,
      });

      // Drop CNAME hops from the answer section so `records` only ever holds
      // the type that was asked for. An unknown code means we have no numeric
      // filter to apply, in which case everything is kept rather than silently
      // discarded.
      const code = TYPE_CODES[type];
      const answers = code == null
        ? (body.Answer ?? [])
        : (body.Answer ?? []).filter((a) => a.type === code);

      return {
        type,
        status: RCODE[body.Status] ?? `RCODE_${body.Status}`,
        records: answers.map((a) => cleanRdata(type, a.data)),
        ttl: answers.length ? Math.min(...answers.map((a) => a.TTL)) : null,
        // The chain of CNAMEs traversed to get here. Needed for takeover
        // detection, where the *target* of the alias is the whole finding.
        aliases: (body.Answer ?? [])
          .filter((a) => a.type === TYPE_CODES.CNAME)
          .map((a) => String(a.data).replace(/\.$/, '').toLowerCase()),
      };
    } catch (err) {
      lastError = err;
    }
  }

  throw new SourceError('dns', `DNS lookup for ${type} failed: ${lastError?.message ?? 'unknown error'}`);
}

/**
 * Numeric RR type codes, used to drop CNAME hops from the answer section.
 *
 * DS and DNSKEY matter here beyond completeness: without their codes the filter
 * above compares against `undefined` and throws away every answer, so a signed
 * zone reports as having no DNSSEC records at all.
 */
const TYPE_CODES = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15,
  TXT: 16, AAAA: 28, SRV: 33, DS: 43, DNSKEY: 48,
  HTTPS: 65, CAA: 257,
};

/** Strip the quoting and trailing dots that DoH returns verbatim from the wire. */
function cleanRdata(type, data) {
  let value = data;
  if (type === 'TXT') {
    // TXT strings arrive quoted, and long values arrive as concatenated chunks.
    value = value.replace(/"\s*"/g, '').replace(/^"|"$/g, '');
  }
  if (type === 'CAA') {
    value = decodeCaa(value);
  }
  if (['NS', 'CNAME', 'PTR', 'MX', 'SOA', 'SRV'].includes(type)) {
    value = value.replace(/\.$/, '').replace(/\.(\s)/g, '$1');
  }
  return value;
}

/**
 * Resolve a batch of names for one record type, tolerating individual failures.
 *
 * Used wherever a lookup fans out over a generated name list — DKIM selectors,
 * SRV service names, discovered subdomains, blocklist zones — where the
 * interesting result is *which* of them answered.
 *
 * @returns {Promise<Array<{name: string, ok: boolean, records: string[], aliases: string[]}>>}
 */
export async function resolveBatch(names, type) {
  const settled = await Promise.allSettled(names.map((name) => resolve(name, type)));
  return settled.map((outcome, i) => ({
    name: names[i],
    ok: outcome.status === 'fulfilled',
    records: outcome.status === 'fulfilled' ? outcome.value.records : [],
    aliases: outcome.status === 'fulfilled' ? (outcome.value.aliases ?? []) : [],
    status: outcome.status === 'fulfilled' ? outcome.value.status : 'ERROR',
  }));
}

/**
 * Decode CAA rdata.
 *
 * Cloudflare's resolver returns CAA in RFC 3597 generic form
 * (`\# 19 00 05 69 73 73 75 65 …`) rather than presentation form, so unpack the
 * wire format ourselves: one flags byte, one tag-length byte, the tag, then the
 * value. Google's resolver already returns presentation form, which falls
 * through unchanged.
 */
function decodeCaa(value) {
  const generic = value.match(/^\\#\s+(\d+)\s+([0-9a-f\s]+)$/i);
  if (!generic) return value;

  const bytes = generic[2].trim().split(/\s+/).map((b) => parseInt(b, 16));
  if (bytes.length < 2 || bytes.some(Number.isNaN)) return value;

  const flags = bytes[0];
  const tagLength = bytes[1];
  if (bytes.length < 2 + tagLength) return value;

  const decode = (slice) => slice.map((b) => String.fromCharCode(b)).join('');
  const tag = decode(bytes.slice(2, 2 + tagLength));
  const tagValue = decode(bytes.slice(2 + tagLength));

  return `${flags} ${tag} "${tagValue}"`;
}

/** Resolve several record types at once, tolerating individual failures. */
export async function resolveMany(name, types) {
  const settled = await Promise.allSettled(types.map((t) => resolve(name, t)));
  const out = {};
  settled.forEach((result, i) => {
    out[types[i]] = result.status === 'fulfilled'
      ? result.value
      : { type: types[i], status: 'ERROR', records: [], ttl: null, error: result.reason?.message };
  });
  return out;
}

/** Build the reverse-lookup name for an IP address. */
export function reverseName(ip, version) {
  if (version === 4) {
    return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
  }
  return `${expandIpv6(ip).replace(/:/g, '').split('').reverse().join('.')}.ip6.arpa`;
}

/** Expand `::` compression to the full 8-group form. */
export function expandIpv6(ip) {
  const [head, tail = ''] = ip.split('::');
  const headGroups = head ? head.split(':').filter(Boolean) : [];
  const tailGroups = tail ? tail.split(':').filter(Boolean) : [];
  const missing = 8 - headGroups.length - tailGroups.length;
  const groups = ip.includes('::')
    ? [...headGroups, ...Array(Math.max(missing, 0)).fill('0'), ...tailGroups]
    : ip.split(':');
  return groups.map((g) => g.padStart(4, '0')).join(':');
}

/** Reverse-DNS a single IP, returning the PTR hostname or null. */
export async function reverseLookup(ip, version) {
  const result = await resolve(reverseName(ip, version), 'PTR');
  return result.records[0] ?? null;
}
