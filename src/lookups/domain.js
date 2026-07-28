/**
 * Domain reconnaissance.
 *
 * This is the module GhostTrack never had. Everything here is passive: it reads
 * public registry data, public DNS and public Certificate Transparency logs.
 * The only packet sent to the target itself is one ordinary HTTPS GET to read
 * security headers — no scanning, no brute force, no bulk enumeration.
 */

import { getJson, getText, request, gather } from '../lib/http.js';
import { resolveMany, resolve } from '../lib/dns.js';
import { parseDomain, registrableDomain } from '../lib/validate.js';
import * as rdap from '../lib/rdap.js';

const RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'DS'];

export async function lookupDomain(input, env = {}) {
  const domain = parseDomain(input);
  const apex = registrableDomain(domain.labels);

  const { data, sources } = await gather({
    registration: () => registration(apex),
    dns: () => resolveMany(domain.value, RECORD_TYPES),
    email: () => emailSecurity(domain.value),
    certificates: () => certificateTransparency(domain.value),
    headers: () => securityHeaders(domain.value),
    securityTxt: () => securityTxt(domain.value),
    archive: () => archiveHistory(domain.value),
    ...(env.VIRUSTOTAL_API_KEY
      ? { reputation: () => virusTotalDomain(domain.value, env.VIRUSTOTAL_API_KEY) }
      : {}),
  });

  // Enrich whatever the domain resolves to. Done after the first wave so we
  // know the addresses; kept to the first few so one domain can't fan out.
  const addresses = [
    ...(data.dns?.A?.records ?? []),
    ...(data.dns?.AAAA?.records ?? []),
  ].slice(0, 4);
  const hosts = await enrichAddresses(addresses);

  return {
    query: { type: 'domain', value: domain.value, apex, isSubdomain: domain.value !== apex },
    registration: data.registration,
    dns: formatDns(data.dns),
    hosting: hosts,
    email: data.email,
    certificates: data.certificates,
    subdomains: data.certificates?.subdomains ?? [],
    httpHeaders: data.headers,
    page: data.headers?.page ?? null,
    securityTxt: data.securityTxt ?? null,
    archive: data.archive ?? null,
    identity: identity(data),
    reputation: data.reputation ?? null,
    assessment: assess(domain.value, data, hosts),
    pivots: pivots(domain.value),
    sources,
  };
}

/* ------------------------------------------------------------------ sources */

async function registration(apex) {
  const body = await rdap.lookup('domain', apex);
  const roles = rdap.entitiesByRole(body.entities);
  const created = rdap.eventDate(body.events, 'registration');
  const expires = rdap.eventDate(body.events, 'expiration');

  return {
    domain: (body.ldhName ?? apex).toLowerCase(),
    handle: body.handle ?? null,
    registrar: roles.registrar?.name ?? roles.registrar?.organization ?? null,
    registrarIana: roles.registrar?.handle ?? null,
    abuseContact: roles.abuse ?? null,
    registrant: redactionAware(roles.registrant),
    administrative: redactionAware(roles.administrative),
    technical: redactionAware(roles.technical),
    created,
    updated: rdap.eventDate(body.events, 'last changed'),
    expires,
    ageDays: created ? daysBetween(created, Date.now()) : null,
    daysUntilExpiry: expires ? daysBetween(Date.now(), expires) : null,
    status: rdap.describeStatus(body.status),
    nameservers: (body.nameservers ?? []).map((ns) => (ns.ldhName ?? '').toLowerCase()).filter(Boolean),
    dnssec: body.secureDNS?.delegationSigned ?? null,
  };
}

/**
 * Post-GDPR, most registrars replace contact details with a privacy service.
 * Distinguish "redacted" from "genuinely absent" so the report is honest.
 */
function redactionAware(contact) {
  if (!contact) return null;
  const blob = JSON.stringify(contact).toLowerCase();
  const redacted = /redact|privacy|gdpr|not disclosed|data protected|whoisguard|withheld/.test(blob);
  return { ...contact, redacted };
}

/** Read the DNS-published email authentication posture. */
async function emailSecurity(domain) {
  const [root, dmarc, mtaSts, bimi] = await Promise.allSettled([
    resolve(domain, 'TXT'),
    resolve(`_dmarc.${domain}`, 'TXT'),
    resolve(`_mta-sts.${domain}`, 'TXT'),
    resolve(`default._bimi.${domain}`, 'TXT'),
  ]);

  const rootTxt = root.status === 'fulfilled' ? root.value.records : [];
  const spfRecord = rootTxt.find((r) => r.toLowerCase().startsWith('v=spf1')) ?? null;
  const dmarcRecord =
    (dmarc.status === 'fulfilled' ? dmarc.value.records : []).find((r) =>
      r.toLowerCase().startsWith('v=dmarc1'),
    ) ?? null;

  return {
    spf: spfRecord ? { record: spfRecord, ...parseSpf(spfRecord) } : null,
    dmarc: dmarcRecord ? { record: dmarcRecord, ...parseDmarc(dmarcRecord) } : null,
    mtaSts:
      mtaSts.status === 'fulfilled'
        ? (mtaSts.value.records.find((r) => r.toLowerCase().startsWith('v=stsv1')) ?? null)
        : null,
    bimi:
      bimi.status === 'fulfilled'
        ? (bimi.value.records.find((r) => r.toLowerCase().startsWith('v=bimi1')) ?? null)
        : null,
    // Domain-verification and service TXT records are useful pivots: they show
    // which SaaS platforms the organisation uses.
    verifications: rootTxt.filter((r) => /verification|-site-verification|-domain-verification/i.test(r)),
  };
}

function parseSpf(record) {
  const all = record.match(/([~\-+?])all\b/);
  const qualifier = all?.[1] ?? null;
  return {
    policy: { '-': 'fail (strict)', '~': 'softfail', '+': 'pass (allows anyone)', '?': 'neutral' }[qualifier] ?? 'no "all" mechanism',
    qualifier,
    // Each `include`/`redirect` costs a DNS lookup; SPF hard-fails past 10.
    includes: [...record.matchAll(/\binclude:([^\s]+)/gi)].map((m) => m[1]),
    lookupCount: (record.match(/\b(include|a|mx|ptr|exists|redirect)[:=]/gi) ?? []).length,
  };
}

function parseDmarc(record) {
  const tag = (name) => record.match(new RegExp(`\\b${name}=([^;\\s]+)`, 'i'))?.[1] ?? null;
  const policy = tag('p');
  return {
    policy,
    subdomainPolicy: tag('sp'),
    percentage: tag('pct') ? Number(tag('pct')) : 100,
    aggregateReports: tag('rua'),
    forensicReports: tag('ruf'),
    alignment: { dkim: tag('adkim') ?? 'r', spf: tag('aspf') ?? 'r' },
    enforcing: policy === 'quarantine' || policy === 'reject',
  };
}

/**
 * Passive subdomain and certificate discovery.
 *
 * Three independent keyless sources run in parallel and their results are
 * merged. crt.sh has the deepest history but routinely times out on large
 * domains, so it is never the only source — Cert Spotter covers recent
 * issuance quickly, and HackerTarget contributes names that resolve today but
 * may predate CT logging. Whatever answers in time contributes; the rest are
 * reported as unavailable rather than failing the panel.
 */
async function certificateTransparency(domain) {
  const [certspotter, crtsh, hostsearch] = await Promise.allSettled([
    certSpotter(domain),
    crtSh(domain),
    hackerTarget(domain),
  ]);

  const names = new Set();
  const contributing = [];
  const failed = [];

  for (const [label, outcome] of [
    ['Cert Spotter', certspotter],
    ['crt.sh', crtsh],
    ['HackerTarget', hostsearch],
  ]) {
    if (outcome.status === 'fulfilled') {
      outcome.value.names.forEach((n) => names.add(n));
      contributing.push({ name: label, found: outcome.value.names.length });
    } else {
      failed.push({ name: label, error: outcome.reason?.message ?? String(outcome.reason) });
    }
  }

  if (!contributing.length) {
    throw new Error(`All discovery sources failed: ${failed.map((f) => f.error).join('; ')}`);
  }

  // Certificate detail comes from whichever CT source answered.
  const certs = (crtsh.status === 'fulfilled' ? crtsh.value.certificates : []).concat(
    certspotter.status === 'fulfilled' ? certspotter.value.certificates : [],
  );

  const issuers = {};
  for (const cert of certs) issuers[cert.issuer] = (issuers[cert.issuer] ?? 0) + 1;

  return {
    totalCertificates: certs.length,
    subdomains: [...names].sort(),
    recentCertificates: certs
      .sort((a, b) => new Date(b.validFrom) - new Date(a.validFrom))
      .slice(0, 6),
    issuers: Object.entries(issuers)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([name, count]) => ({ name, count })),
    discoverySources: contributing,
    unavailableSources: failed,
  };
}

/** SSLMate's Cert Spotter: fast, keyless for recent issuance. */
async function certSpotter(domain) {
  const body = await getJson(
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
      '&include_subdomains=true&expand=dns_names&expand=issuer',
    { source: 'certspotter.com', timeout: 9000 },
  );

  const entries = Array.isArray(body) ? body : [];
  const names = new Set();
  const certificates = [];

  for (const entry of entries) {
    for (const name of entry.dns_names ?? []) names.add(normalizeName(name, domain));
    certificates.push({
      commonName: entry.dns_names?.[0] ?? null,
      issuer: entry.issuer?.friendly_name ?? shortIssuer(entry.issuer?.name),
      validFrom: entry.not_before ?? null,
      validTo: entry.not_after ?? null,
      serial: null,
      source: 'Cert Spotter',
    });
  }

  return { names: [...names].filter(Boolean), certificates };
}

/** crt.sh: deepest CT history, but slow — kept on a short leash. */
async function crtSh(domain) {
  const body = await getJson(
    `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&exclude=expired&deduplicate=Y`,
    { source: 'crt.sh', timeout: 10000 },
  );

  const entries = Array.isArray(body) ? body : [];
  const names = new Set();

  for (const entry of entries) {
    for (const name of String(entry.name_value ?? '').split('\n')) {
      names.add(normalizeName(name, domain));
    }
  }

  const certificates = entries.slice(0, 200).map((e) => ({
    commonName: e.common_name ?? null,
    issuer: shortIssuer(e.issuer_name),
    validFrom: e.not_before ?? null,
    validTo: e.not_after ?? null,
    serial: e.serial_number ?? null,
    source: 'crt.sh',
  }));

  return { names: [...names].filter(Boolean), certificates };
}

/** HackerTarget hostsearch: names that resolve now, from passive DNS. */
async function hackerTarget(domain) {
  const text = await getText(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, {
    source: 'hackertarget.com',
    timeout: 8000,
  });

  // The free endpoint signals quota exhaustion as a plain-text error body.
  if (/API count exceeded|error/i.test(text)) {
    throw new Error('HackerTarget quota exceeded for this source address');
  }

  const names = text
    .split('\n')
    .map((line) => normalizeName(line.split(',')[0] ?? '', domain))
    .filter(Boolean);

  return { names: [...new Set(names)], certificates: [] };
}

/** Lower-case, de-wildcard, and reject anything outside the queried domain. */
function normalizeName(name, domain) {
  const clean = String(name).trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  if (!clean || clean.includes(' ') || !clean.endsWith(domain)) return null;
  return clean;
}

function shortIssuer(issuerName = '') {
  return issuerName?.match(/O\s*=\s*"?([^,"]+)/)?.[1]?.trim() ?? String(issuerName).slice(0, 60);
}

/**
 * One plain HTTPS GET of the site root, read twice over: for the security
 * header posture, and for what the page itself discloses.
 *
 * The HTML is the single richest attribution source in a domain lookup — the
 * organisation usually names itself in the title, og:site_name or copyright
 * line, and the analytics IDs embedded in the page are a strong ownership
 * pivot. All of it comes from a request we were already making.
 */
async function securityHeaders(domain) {
  const response = await request(`https://${domain}/`, {
    source: domain,
    timeout: 8000,
    headers: { accept: 'text/html,*/*' },
  });

  const h = response.headers;
  const present = (name) => h.get(name) ?? null;

  // Read a bounded slice: enough for <head> and the analytics snippets, without
  // pulling a multi-megabyte page into a Worker.
  let html = '';
  if ((h.get('content-type') ?? '').includes('html')) {
    html = await readCapped(response, 250_000);
  }

  return {
    page: html ? describePage(html) : null,
    status: response.status,
    finalUrl: response.url,
    server: present('server'),
    poweredBy: present('x-powered-by'),
    strictTransportSecurity: present('strict-transport-security'),
    contentSecurityPolicy: present('content-security-policy') ? 'present' : null,
    xFrameOptions: present('x-frame-options'),
    xContentTypeOptions: present('x-content-type-options'),
    referrerPolicy: present('referrer-policy'),
    permissionsPolicy: present('permissions-policy') ? 'present' : null,
    // A CDN in front changes what every other signal means, so name it.
    cdn: detectCdn(h),
    cookies: h.getSetCookie?.().length ?? (h.get('set-cookie') ? 1 : 0),
  };
}

/** Read at most `limit` bytes of a response body, then stop. */
async function readCapped(response, limit) {
  const reader = response.body?.getReader();
  if (!reader) return '';

  const decoder = new TextDecoder();
  let out = '';
  try {
    while (out.length < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      out += decoder.decode(value, { stream: true });
    }
  } catch {
    // A truncated read still gives us a usable <head>.
  } finally {
    reader.cancel().catch(() => {});
  }
  return out.slice(0, limit);
}

/** Pull identity and ownership signals out of the page source. */
function describePage(html) {
  const head = html.slice(0, 120_000);

  const meta = (attr, name) => {
    const pattern = new RegExp(
      `<meta[^>]+${attr}\\s*=\\s*["']${name}["'][^>]*content\\s*=\\s*["']([^"']{1,300})["']`,
      'i',
    );
    const reversed = new RegExp(
      `<meta[^>]+content\\s*=\\s*["']([^"']{1,300})["'][^>]*${attr}\\s*=\\s*["']${name}["']`,
      'i',
    );
    return head.match(pattern)?.[1]?.trim() ?? head.match(reversed)?.[1]?.trim() ?? null;
  };

  const unique = (values) => [...new Set(values)];

  // Analytics and tag IDs are among the strongest ownership pivots available:
  // the same measurement ID across two sites is good evidence of a common
  // operator. Searchable on publicwww / SpyOnWeb / Analyzeid.
  const trackers = [
    ...[...html.matchAll(/\b(G-[A-Z0-9]{6,12})\b/g)].map((m) => ({ type: 'Google Analytics 4', id: m[1] })),
    ...[...html.matchAll(/\b(UA-\d{4,10}-\d{1,4})\b/g)].map((m) => ({ type: 'Google Analytics (legacy)', id: m[1] })),
    ...[...html.matchAll(/\b(GTM-[A-Z0-9]{4,10})\b/g)].map((m) => ({ type: 'Google Tag Manager', id: m[1] })),
    ...[...html.matchAll(/fbq\(\s*['"]init['"]\s*,\s*['"](\d{8,20})['"]/g)].map((m) => ({ type: 'Meta Pixel', id: m[1] })),
    ...[...html.matchAll(/hjid\s*:\s*(\d{5,10})/g)].map((m) => ({ type: 'Hotjar', id: m[1] })),
  ];

  const seen = new Set();
  const trackingIds = trackers.filter((t) => !seen.has(t.id) && seen.add(t.id)).slice(0, 12);

  return {
    title: head.match(/<title[^>]*>([\s\S]{1,300}?)<\/title>/i)?.[1]?.replace(/\s+/g, ' ').trim() ?? null,
    description: meta('name', 'description'),
    siteName: meta('property', 'og:site_name') ?? meta('name', 'application-name'),
    ogTitle: meta('property', 'og:title'),
    author: meta('name', 'author'),
    // `generator` names the CMS or site builder outright.
    generator: meta('name', 'generator'),
    themeColor: meta('name', 'theme-color'),
    language: html.match(/<html[^>]+lang\s*=\s*["']([a-z-]{2,10})["']/i)?.[1] ?? null,
    // A copyright line often carries the legal entity name.
    copyright: unique(
      [...html.matchAll(/(?:©|&copy;|Copyright)\s*(?:\d{4}(?:\s*[–—-]\s*\d{4})?)?\s*([A-Z][A-Za-z0-9.,'&\- ]{2,60}?)(?:\.|<|,\s*(?:All|Inc|LLC|Ltd))/g)]
        .map((m) => m[1].trim())
        .filter((v) => v.length > 2),
    ).slice(0, 3),
    // Contact addresses published on the page are legitimate public disclosure.
    // Placeholder addresses from form markup and docs are noise, not contacts.
    emails: unique(
      [...html.matchAll(/\b([a-z0-9][\w.+-]{0,40}@[a-z0-9][\w.-]{0,60}\.[a-z]{2,12})\b/gi)]
        .map((m) => m[1].toLowerCase())
        .filter((e) => !/\.(png|jpe?g|gif|svg|webp|css|js)$/i.test(e))
        .filter((e) => !/@(example|yourdomain|domain|email|test|sample|placeholder)\.(com|org|net)$/.test(e))
        .filter((e) => !/^(you|user|name|email|someone|john\.?doe)@/.test(e)),
    ).slice(0, 10),
    socialProfiles: unique(
      [...html.matchAll(/https?:\/\/(?:www\.)?(twitter\.com|x\.com|linkedin\.com|github\.com|facebook\.com|instagram\.com|youtube\.com|mastodon\.social)\/([A-Za-z0-9_.\-\/]{2,60})/g)]
        .map((m) => `https://${m[1]}/${m[2]}`.replace(/[/.]+$/, '')),
    ).slice(0, 12),
    trackingIds,
  };
}

/**
 * RFC 9116 security.txt. Frequently names a security contact — a person, a
 * team address, or a disclosure programme — that RDAP redaction hides.
 */
async function securityTxt(domain) {
  let text;
  try {
    text = await getText(`https://${domain}/.well-known/security.txt`, {
      source: `${domain}/.well-known/security.txt`,
      timeout: 6000,
    });
  } catch {
    return null;
  }

  // A site that serves its SPA shell for every path will return HTML here.
  if (/<html|<!doctype/i.test(text) || text.length > 20_000) return null;

  const field = (name) =>
    [...text.matchAll(new RegExp(`^${name}\\s*:\\s*(.+)$`, 'gim'))]
      .map((m) => m[1].trim())
      .filter(Boolean);

  const contacts = field('Contact');
  if (!contacts.length) return null;

  return {
    contacts,
    expires: field('Expires')[0] ?? null,
    encryption: field('Encryption')[0] ?? null,
    policy: field('Policy')[0] ?? null,
    acknowledgments: field('Acknowledgments')[0] ?? null,
    preferredLanguages: field('Preferred-Languages')[0] ?? null,
    hiring: field('Hiring')[0] ?? null,
  };
}

/**
 * Internet Archive coverage. RDAP gives the registration date of the *current*
 * registration; the archive shows when content actually first appeared, which
 * is what matters when a domain has been dropped and re-registered.
 */
async function archiveHistory(domain) {
  // Two tiny "closest snapshot" queries rather than one CDX range query. The
  // CDX endpoint returns the full capture list, is slow on large sites, and is
  // aggressively rate-limited — unworkable from shared egress like a Worker.
  // This costs two cheap requests and yields the dates that actually matter.
  const at = async (timestamp) => {
    const text = await getText(
      `https://archive.org/wayback/available?url=${encodeURIComponent(domain)}&timestamp=${timestamp}`,
      { source: 'archive.org', timeout: 8000 },
    );
    if (/^\s*</.test(text)) throw new Error('archive.org rate-limited this lookup');
    return JSON.parse(text)?.archived_snapshots?.closest ?? null;
  };

  const [earliest, latest] = await Promise.all([at('1996'), at('20991231')]);
  if (!earliest && !latest) return { archived: false, firstSeen: null, lastSeen: null };

  const toIso = (s) => (s ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}` : null);
  return {
    archived: true,
    firstSeen: toIso(earliest?.timestamp),
    lastSeen: toIso(latest?.timestamp),
    firstSnapshotUrl: earliest?.url ?? null,
    url: `https://web.archive.org/web/*/${domain}`,
  };
}

function detectCdn(headers) {
  if (headers.get('cf-ray')) return 'Cloudflare';
  if (headers.get('x-amz-cf-id')) return 'Amazon CloudFront';
  if (headers.get('x-fastly-request-id') || /fastly/i.test(headers.get('x-served-by') ?? '')) return 'Fastly';
  if (/akamai/i.test(headers.get('server') ?? '') || headers.get('x-akamai-transformed')) return 'Akamai';
  if (headers.get('x-vercel-id')) return 'Vercel';
  if (headers.get('x-nf-request-id')) return 'Netlify';
  if (headers.get('x-github-request-id')) return 'GitHub Pages';
  return null;
}

async function virusTotalDomain(domain, key) {
  const body = await getJson(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
    source: 'virustotal.com',
    headers: { 'x-apikey': key },
  });
  const stats = body.data?.attributes?.last_analysis_stats ?? {};
  return {
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    reputation: body.data?.attributes?.reputation ?? null,
  };
}

/** Attach geo + exposure to each resolved address. */
async function enrichAddresses(addresses) {
  const settled = await Promise.allSettled(
    addresses.map(async (address) => {
      const [geo, exposure] = await Promise.allSettled([
        getJson(`https://ipwho.is/${encodeURIComponent(address)}`, { source: 'ipwho.is', timeout: 7000 }),
        getJson(`https://internetdb.shodan.io/${encodeURIComponent(address)}`, { source: 'internetdb.shodan.io', timeout: 7000 }),
      ]);
      const g = geo.status === 'fulfilled' && geo.value.success !== false ? geo.value : null;
      const e = exposure.status === 'fulfilled' ? exposure.value : null;
      return {
        address,
        country: g?.country ?? null,
        flag: g?.flag?.emoji ?? null,
        city: g?.city ?? null,
        organization: g?.connection?.org ?? g?.connection?.isp ?? null,
        asn: g?.connection?.asn ? `AS${g.connection.asn}` : null,
        ports: e?.ports ?? [],
        vulnerabilities: e?.vulns ?? [],
      };
    }),
  );
  return settled.filter((s) => s.status === 'fulfilled').map((s) => s.value);
}

function formatDns(dns) {
  if (!dns) return null;
  const out = {};
  for (const [type, result] of Object.entries(dns)) {
    out[type] = { records: result.records, ttl: result.ttl, status: result.status };
  }
  return out;
}

/* ------------------------------------------------------------------ identity */

/**
 * Consolidate every attribution signal into one ranked view.
 *
 * RDAP registrant data is redacted for most gTLDs post-GDPR, so the answer to
 * "who runs this domain" usually has to be assembled from what the operator
 * publishes voluntarily: the site's own metadata, its copyright line, its
 * security.txt contact. Each candidate carries the source it came from and how
 * far it can be trusted, because these differ enormously — a registry
 * registrant field is authoritative, a copyright string is a guess.
 */
function identity(data) {
  const page = data.headers?.page ?? null;
  const reg = data.registration ?? null;
  const names = [];

  const add = (value, source, confidence) => {
    if (!value) return;
    const clean = String(value).trim();
    if (clean.length < 2 || clean.length > 120) return;
    if (names.some((n) => n.value.toLowerCase() === clean.toLowerCase())) return;
    names.push({ value: clean, source, confidence });
  };

  // Authoritative when present — but usually redacted.
  if (reg?.registrant && !reg.registrant.redacted) {
    add(reg.registrant.organization ?? reg.registrant.name, 'RDAP registrant', 'high');
  }
  if (reg?.administrative && !reg.administrative.redacted) {
    add(reg.administrative.organization ?? reg.administrative.name, 'RDAP admin contact', 'high');
  }

  // Self-declared, and generally accurate — the operator wrote it.
  add(page?.siteName, 'og:site_name', 'medium');
  page?.copyright?.forEach((c) => add(c, 'copyright notice', 'medium'));
  add(page?.author, 'author meta tag', 'medium');

  // Weakest: a title is marketing copy, not a legal entity.
  add(page?.title?.split(/\s[|·—–-]\s/)[0], 'page title', 'low');

  const contacts = [];
  for (const contact of data.securityTxt?.contacts ?? []) {
    contacts.push({ value: contact.replace(/^mailto:/, ''), source: 'security.txt', role: 'security' });
  }
  if (reg?.abuseContact?.email) {
    contacts.push({ value: reg.abuseContact.email, source: 'RDAP registrar abuse', role: 'abuse' });
  }
  for (const email of page?.emails ?? []) {
    contacts.push({ value: email, source: 'page source', role: 'published' });
  }

  return {
    names,
    contacts: contacts.slice(0, 12),
    socialProfiles: page?.socialProfiles ?? [],
    trackingIds: page?.trackingIds ?? [],
    // Say plainly why the registrant is missing, rather than showing a blank.
    registrantStatus: reg?.registrant?.redacted
      ? 'redacted'
      : reg?.registrant
        ? 'published'
        : 'not published',
  };
}

/* --------------------------------------------------------------- assessment */

function assess(domain, data, hosts) {
  const findings = [];
  const reg = data.registration;

  if (reg?.ageDays != null && reg.ageDays < 90) {
    findings.push({
      level: 'warn',
      title: `Registered ${reg.ageDays} day${reg.ageDays === 1 ? '' : 's'} ago`,
      detail: 'Newly registered domains are disproportionately represented in phishing and fraud. Weigh other signals accordingly.',
    });
  }
  if (reg?.daysUntilExpiry != null && reg.daysUntilExpiry < 30) {
    findings.push({
      level: reg.daysUntilExpiry < 0 ? 'danger' : 'warn',
      title: reg.daysUntilExpiry < 0 ? 'Registration has expired' : `Expires in ${reg.daysUntilExpiry} days`,
      detail: 'An expiring domain can be lost, re-registered by a third party, or dropped from DNS.',
    });
  }
  if (reg && reg.dnssec === false) {
    findings.push({ level: 'info', title: 'DNSSEC not enabled', detail: 'Responses for this zone are not cryptographically signed.' });
  }

  const email = data.email;
  if (email) {
    if (!email.spf) {
      findings.push({ level: 'warn', title: 'No SPF record', detail: 'Nothing declares which servers may send mail as this domain.' });
    } else if (email.spf.qualifier === '+') {
      findings.push({ level: 'danger', title: 'SPF allows any sender', detail: 'The record ends in `+all`, which authorises every host on the internet to send as this domain.' });
    } else if (email.spf.lookupCount > 10) {
      findings.push({ level: 'warn', title: `SPF exceeds the 10-lookup limit (${email.spf.lookupCount})`, detail: 'Receivers must treat over-limit SPF as a permerror, so authentication will fail.' });
    }

    if (!email.dmarc) {
      findings.push({ level: 'warn', title: 'No DMARC record', detail: 'Without DMARC, receivers have no published instruction for handling spoofed mail from this domain.' });
    } else if (!email.dmarc.enforcing) {
      findings.push({ level: 'warn', title: `DMARC is monitor-only (p=${email.dmarc.policy})`, detail: 'The policy is published but not enforced, so spoofed mail is still delivered.' });
    } else if (email.dmarc.percentage < 100) {
      findings.push({ level: 'info', title: `DMARC applied to only ${email.dmarc.percentage}% of mail`, detail: 'A partial rollout — `pct` is below 100.' });
    }
    if (!email.dmarc && !email.spf && !(data.dns?.MX?.records ?? []).length) {
      findings.push({ level: 'info', title: 'No mail configuration', detail: 'No MX, SPF or DMARC records — this domain does not appear to send or receive email.' });
    }
  }

  if (!(data.dns?.CAA?.records ?? []).length) {
    findings.push({ level: 'info', title: 'No CAA record', detail: 'Any certificate authority may issue certificates for this domain.' });
  }

  const headers = data.httpHeaders;
  if (headers) {
    const missing = [];
    if (!headers.strictTransportSecurity) missing.push('HSTS');
    if (!headers.contentSecurityPolicy) missing.push('Content-Security-Policy');
    if (!headers.xContentTypeOptions) missing.push('X-Content-Type-Options');
    if (missing.length) {
      findings.push({ level: 'info', title: `Missing security headers: ${missing.join(', ')}`, detail: 'Present headers were read from a single HTTPS GET of the site root.' });
    }
    if (headers.poweredBy) {
      findings.push({ level: 'info', title: 'Server software disclosed', detail: `\`X-Powered-By: ${headers.poweredBy}\` leaks the backend stack.` });
    }
  }

  // A site archived long before its current registration date is a re-registered
  // or transferred domain — the registration date understates its real history,
  // and the current owner may be unrelated to the archived content.
  const archived = data.archive;
  if (archived?.firstSeen && reg?.created) {
    const gapDays = daysBetween(archived.firstSeen, reg.created);
    if (gapDays > 365) {
      findings.push({
        level: 'info',
        title: `Archived since ${archived.firstSeen}, ${Math.floor(gapDays / 365)} years before the current registration`,
        detail: 'The domain was in use well before the registration on record, so it has been re-registered or transferred. Archived content may belong to a previous owner.',
      });
    }
  }

  const identified = data.headers?.page;
  if (identified?.trackingIds?.length) {
    findings.push({
      level: 'info',
      title: `${identified.trackingIds.length} analytics ID${identified.trackingIds.length === 1 ? '' : 's'} in the page source`,
      detail: 'The same measurement ID appearing on another site is good evidence of a shared operator. Searchable on publicwww.com and analyzeid.com.',
    });
  }

  if (data.securityTxt?.contacts?.length) {
    findings.push({
      level: 'info',
      title: 'Publishes security.txt',
      detail: `Security contact: ${data.securityTxt.contacts[0]}. A named disclosure channel usually indicates a maintained, staffed domain.`,
    });
  }

  const subCount = data.certificates?.subdomains?.length ?? 0;
  if (subCount) {
    findings.push({ level: 'info', title: `${subCount} subdomain${subCount === 1 ? '' : 's'} in Certificate Transparency`, detail: 'Names observed in publicly-logged certificates. Some may no longer resolve.' });
  }

  const vulnHosts = hosts.filter((h) => h.vulnerabilities.length);
  if (vulnHosts.length) {
    findings.push({
      level: 'danger',
      title: 'Known CVEs on resolved hosts',
      detail: vulnHosts.map((h) => `${h.address}: ${h.vulnerabilities.slice(0, 5).join(', ')}`).join(' · '),
    });
  }

  if (data.reputation?.malicious > 0) {
    findings.push({ level: 'danger', title: `Flagged by ${data.reputation.malicious} security vendor(s)`, detail: `${data.reputation.harmless} vendors rate it harmless.` });
  }

  if (!findings.some((f) => f.level === 'warn' || f.level === 'danger')) {
    findings.unshift({ level: 'ok', title: 'No material issues found', detail: 'Registration, DNS and email authentication all look conventional.' });
  }
  return findings;
}

function daysBetween(from, to) {
  return Math.floor((new Date(to) - new Date(from)) / 86_400_000);
}

function pivots(domain) {
  return [
    { label: 'crt.sh', url: `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}` },
    { label: 'VirusTotal', url: `https://www.virustotal.com/gui/domain/${domain}` },
    { label: 'urlscan.io', url: `https://urlscan.io/domain/${domain}` },
    { label: 'Wayback Machine', url: `https://web.archive.org/web/*/${domain}` },
    { label: 'Shodan', url: `https://www.shodan.io/search?query=hostname%3A${encodeURIComponent(domain)}` },
    { label: 'SecurityTrails', url: `https://securitytrails.com/domain/${domain}/dns` },
    { label: 'BuiltWith', url: `https://builtwith.com/${domain}` },
  ];
}
