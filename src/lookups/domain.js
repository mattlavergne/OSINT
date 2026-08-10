/**
 * Domain reconnaissance.
 *
 * This is the module GhostTrack never had. Everything here is passive: it reads
 * public registry data, public DNS, public Certificate Transparency logs, and
 * the files a site publishes at conventional public paths. The only packets
 * sent to the target are ordinary HTTPS GETs of documents it serves to any
 * browser — no scanning, no brute force, no bulk enumeration.
 */

import { getJson, getText, getBytes, requestChain, readCapped, gather } from '../lib/http.js';
import { resolveMany, resolve, resolveBatch } from '../lib/dns.js';
import { parseDomain, registrableDomain } from '../lib/validate.js';
import { faviconHash } from '../lib/hash.js';
import {
  DKIM_SELECTORS, SRV_SERVICES, TAKEOVER_SIGNATURES, WELL_KNOWN_FILES,
  fingerprint, mailProvider, dnsProvider,
} from '../lib/providers.js';
import * as rdap from '../lib/rdap.js';

const RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'DS'];

/**
 * Subdomain names worth resolving first.
 *
 * Certificate Transparency routinely returns hundreds of names and only a
 * bounded number can be resolved. Ranking matters more than the cap: these are
 * the prefixes that sit in front of the interesting things — remote access,
 * internal tooling, pre-production, and the un-fronted origin behind a CDN.
 */
const INTERESTING_PREFIXES = [
  'vpn', 'remote', 'access', 'gateway', 'portal', 'sso', 'auth', 'login', 'idp',
  'admin', 'manage', 'cpanel', 'webmail', 'mail', 'smtp', 'imap', 'exchange',
  'dev', 'test', 'staging', 'stage', 'uat', 'qa', 'sandbox', 'preprod', 'beta',
  'internal', 'intranet', 'corp', 'private', 'old', 'legacy', 'backup',
  'api', 'git', 'gitlab', 'jenkins', 'ci', 'jira', 'confluence', 'grafana',
  'kibana', 'prometheus', 'vault', 'db', 'database', 'sql', 'ftp', 'sftp',
  'origin', 'direct', 'srv', 'server', 'host', 'ns', 'router', 'firewall',
  'monitor', 'status', 'metrics', 'log', 'logs', 'proxy', 'cdn', 'static',
];

export async function lookupDomain(input, env = {}, options = {}) {
  const domain = parseDomain(input);
  const apex = registrableDomain(domain.labels);
  const deep = options.depth === 'deep';

  const { data, sources } = await gather({
    registration: () => registration(apex),
    dns: () => resolveMany(domain.value, RECORD_TYPES),
    email: () => emailSecurity(domain.value),
    certificates: () => certificateTransparency(domain.value),
    headers: () => siteResponse(domain.value),
    securityTxt: () => securityTxt(domain.value),
    archive: () => archiveHistory(domain.value),
    scans: () => urlScan(domain.value),
    lookalikes: () => lookalikes(apex, deep ? 10 : 4),
    publicFiles: () => wellKnownFiles(domain.value, deep),
    favicon: () => faviconFingerprint(domain.value),
    wildcard: () => wildcardCheck(domain.value),
    ...(deep ? { dkim: () => dkimSelectors(domain.value) } : {}),
    ...(deep ? { srv: () => srvServices(domain.value) } : {}),
    ...(deep ? { dnskey: () => resolve(domain.value, 'DNSKEY') } : {}),
    ...(env.VIRUSTOTAL_API_KEY
      ? { reputation: () => virusTotalDomain(domain.value, env.VIRUSTOTAL_API_KEY) }
      : {}),
  });

  // Second wave: everything that needs the first wave's answers.
  const addresses = [
    ...(data.dns?.A?.records ?? []),
    ...(data.dns?.AAAA?.records ?? []),
  ].slice(0, deep ? 4 : 2);

  const [hosts, subdomainDetail] = await Promise.all([
    enrichAddresses(addresses),
    deep
      ? mapSubdomains(data.certificates?.subdomains ?? [], domain.value, addresses)
      : null,
  ]);
  if (deep) sources.subdomainMap = { ok: subdomainDetail !== null };

  const page = data.headers?.page ?? null;

  return {
    query: { type: 'domain', value: domain.value, apex, isSubdomain: domain.value !== apex, depth: options.depth ?? 'standard' },
    registration: data.registration,
    dns: formatDns(data.dns),
    dnssec: dnssecPosture(data),
    wildcard: data.wildcard ?? null,
    providers: identifyProviders(data),
    hosting: hosts,
    email: data.email,
    dkim: data.dkim ?? null,
    services: data.srv ?? null,
    certificates: data.certificates,
    subdomains: data.certificates?.subdomains ?? [],
    subdomainDetail,
    // Other registrable domains that share a TLS certificate with this one.
    relatedDomains: data.certificates?.relatedDomains ?? [],
    httpHeaders: data.headers,
    redirectChain: data.headers?.chain ?? null,
    technologies: data.headers?.technologies ?? [],
    page,
    structuredData: page?.structuredData ?? null,
    favicon: data.favicon ?? null,
    publicFiles: data.publicFiles ?? null,
    securityTxt: data.securityTxt ?? null,
    archive: data.archive ?? null,
    scans: data.scans ?? null,
    lookalikes: data.lookalikes ?? null,
    identity: identity(data),
    reputation: data.reputation ?? null,
    assessment: assess(domain.value, data, hosts, subdomainDetail),
    pivots: pivots(domain.value, data.favicon),
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
    reseller: roles.reseller?.name ?? null,
    created,
    updated: rdap.eventDate(body.events, 'last changed'),
    expires,
    transferred: rdap.eventDate(body.events, 'transfer'),
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
    // Every TXT record, so nothing is hidden behind the filters above.
    allTxt: rootTxt.slice(0, 40),
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
    // Hardcoded senders are a direct list of the organisation's own mail
    // infrastructure, which nothing else in DNS enumerates.
    ipv4: [...record.matchAll(/\bip4:([^\s]+)/gi)].map((m) => m[1]),
    ipv6: [...record.matchAll(/\bip6:([^\s]+)/gi)].map((m) => m[1]),
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
    // The reporting address often belongs to a third-party DMARC vendor, and
    // sometimes to a different corporate domain — a genuine ownership link.
    reportingDomains: [...new Set(
      [tag('rua'), tag('ruf')].filter(Boolean).join(',')
        .split(',')
        .map((uri) => uri.trim().replace(/^mailto:/i, '').split('@')[1])
        .filter(Boolean),
    )],
  };
}

/**
 * DKIM selector discovery.
 *
 * DKIM keys live at `<selector>._domainkey.<domain>` and the selector is chosen
 * by the sending platform, so the selectors that resolve are a direct list of
 * every service authorised to send mail as this domain — including internal
 * tools that appear nowhere else in DNS. There is no way to enumerate
 * selectors; you check the conventional name each platform uses.
 */
async function dkimSelectors(domain) {
  const candidates = DKIM_SELECTORS.slice(0, 16);
  const results = await resolveBatch(
    candidates.map((c) => `${c.selector}._domainkey.${domain}`),
    'TXT',
  );

  const found = [];
  results.forEach((result, i) => {
    const record = result.records.find((r) => /v=DKIM1|[;\s]p=/i.test(r));
    if (!record) return;

    const keyType = record.match(/\bk=([a-z0-9]+)/i)?.[1] ?? 'rsa';
    const key = record.match(/\bp=([A-Za-z0-9+/=]*)/)?.[1] ?? '';

    found.push({
      selector: candidates[i].selector,
      platform: candidates[i].platform,
      keyType,
      // An empty p= is a revoked key: the selector existed and was retired,
      // which still tells you the platform was once in use.
      revoked: key.length === 0,
      keyBits: key ? estimateKeyBits(key) : null,
    });
  });

  return { checked: candidates.length, found, platforms: [...new Set(found.map((f) => f.platform))] };
}

/** Rough modulus size from a base64 DER public key, for weak-key detection. */
function estimateKeyBits(base64Key) {
  const bytes = Math.floor((base64Key.replace(/=+$/, '').length * 3) / 4);
  if (bytes > 380) return 4096;
  if (bytes > 240) return 2048;
  if (bytes > 150) return 1024;
  return 512;
}

/**
 * SRV service discovery.
 *
 * Each SRV name that resolves maps a service the organisation runs and, in the
 * record's target, the host that runs it — an internal collaboration stack that
 * A and MX records never expose.
 */
async function srvServices(domain) {
  const results = await resolveBatch(
    SRV_SERVICES.map((s) => `${s.name}.${domain}`),
    'SRV',
  );

  const found = [];
  results.forEach((result, i) => {
    for (const record of result.records) {
      // priority weight port target
      const [priority, weight, port, ...rest] = record.split(/\s+/);
      const target = rest.join(' ').replace(/\.$/, '');
      if (!target || target === '.') continue;

      // `|| null` would discard a legitimate zero, and zero is the usual value
      // for both SRV priority and weight.
      const number = (value) => (Number.isFinite(Number(value)) ? Number(value) : null);

      found.push({
        service: SRV_SERVICES[i].label,
        name: SRV_SERVICES[i].name,
        target,
        port: number(port),
        priority: number(priority),
        weight: number(weight),
      });
    }
  });

  return { checked: SRV_SERVICES.length, found };
}

/**
 * Wildcard DNS detection.
 *
 * A zone that answers for every possible name makes subdomain enumeration
 * meaningless — every guess "resolves". Detecting it costs one lookup of a name
 * nobody would ever register, and it changes how the whole subdomain section
 * should be read.
 */
async function wildcardCheck(domain) {
  const probe = `gt-${Math.random().toString(36).slice(2, 12)}.${domain}`;
  const result = await resolve(probe, 'A');
  return {
    wildcard: result.records.length > 0,
    probe,
    addresses: result.records,
    note: result.records.length
      ? 'This zone answers for names that do not exist, so a subdomain resolving is not evidence that it was ever configured.'
      : 'Non-existent names correctly return NXDOMAIN, so resolution is meaningful.',
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
  const foreign = new Set();
  const contributing = [];
  const failed = [];

  for (const [label, outcome] of [
    ['Cert Spotter', certspotter],
    ['crt.sh', crtsh],
    ['HackerTarget', hostsearch],
  ]) {
    if (outcome.status === 'fulfilled') {
      outcome.value.names.forEach((n) => names.add(n));
      // Names on the same certificate that sit outside this domain entirely.
      outcome.value.foreign?.forEach((n) => foreign.add(n));
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

  // A certificate covering two unrelated domains is issued by whoever controls
  // both — one of the strongest ownership links available from public logs.
  const relatedDomains = [...foreign]
    .map((name) => registrableDomain(name.split('.')))
    .filter((name, i, all) => name !== domain && all.indexOf(name) === i)
    .slice(0, 40);

  return {
    totalCertificates: certs.length,
    subdomains: [...names].sort(),
    relatedDomains,
    recentCertificates: certs
      .sort((a, b) => new Date(b.validFrom) - new Date(a.validFrom))
      .slice(0, 8),
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
  const foreign = new Set();
  const certificates = [];

  for (const entry of entries) {
    for (const name of entry.dns_names ?? []) {
      const clean = normalizeName(name, domain);
      if (clean) names.add(clean);
      else collectForeign(name, domain, foreign);
    }
    certificates.push({
      commonName: entry.dns_names?.[0] ?? null,
      names: (entry.dns_names ?? []).slice(0, 12),
      issuer: entry.issuer?.friendly_name ?? shortIssuer(entry.issuer?.name),
      validFrom: entry.not_before ?? null,
      validTo: entry.not_after ?? null,
      serial: null,
      source: 'Cert Spotter',
    });
  }

  return { names: [...names].filter(Boolean), foreign: [...foreign], certificates };
}

/** crt.sh: deepest CT history, but slow — kept on a short leash. */
async function crtSh(domain) {
  const body = await getJson(
    `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&exclude=expired&deduplicate=Y`,
    { source: 'crt.sh', timeout: 10000 },
  );

  const entries = Array.isArray(body) ? body : [];
  const names = new Set();
  const foreign = new Set();

  for (const entry of entries) {
    for (const name of String(entry.name_value ?? '').split('\n')) {
      const clean = normalizeName(name, domain);
      if (clean) names.add(clean);
      else collectForeign(name, domain, foreign);
    }
  }

  const certificates = entries.slice(0, 200).map((e) => ({
    commonName: e.common_name ?? null,
    names: String(e.name_value ?? '').split('\n').slice(0, 12),
    issuer: shortIssuer(e.issuer_name),
    validFrom: e.not_before ?? null,
    validTo: e.not_after ?? null,
    serial: e.serial_number ?? null,
    source: 'crt.sh',
  }));

  return { names: [...names].filter(Boolean), foreign: [...foreign], certificates };
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

  return { names: [...new Set(names)], foreign: [], certificates: [] };
}

/** Lower-case, de-wildcard, and reject anything outside the queried domain. */
function normalizeName(name, domain) {
  const clean = String(name).trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  if (!clean || clean.includes(' ') || !clean.endsWith(domain)) return null;
  return clean;
}

/** Names on the certificate belonging to some *other* domain entirely. */
function collectForeign(name, domain, into) {
  const clean = String(name).trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  if (!clean || clean.includes(' ') || !clean.includes('.')) return;
  if (clean.endsWith(domain)) return;
  if (!/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(clean)) return;
  into.add(clean);
}

function shortIssuer(issuerName = '') {
  return issuerName?.match(/O\s*=\s*"?([^,"]+)/)?.[1]?.trim() ?? String(issuerName).slice(0, 60);
}

/**
 * One HTTPS GET of the site root, read for everything it will give up: the
 * redirect route, the security header posture, the technology stack, and what
 * the page itself discloses.
 *
 * The HTML is the single richest attribution source in a domain lookup — the
 * organisation usually names itself in the title, og:site_name, its JSON-LD
 * block or its copyright line, and the analytics and service IDs embedded in
 * the page are a strong ownership pivot. All of it comes from a request we were
 * already making.
 */
async function siteResponse(domain) {
  const { response, chain } = await requestChain(`https://${domain}/`, {
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
    html = await readCapped(response, 300_000);
  }

  const cookies = (h.getSetCookie?.() ?? [h.get('set-cookie')].filter(Boolean)).join('; ');

  return {
    page: html ? describePage(html, domain) : null,
    technologies: fingerprint({ headers: h, html, cookies }),
    chain: chain.length > 1 ? chain : null,
    status: response.status,
    finalUrl: chain[chain.length - 1]?.url ?? response.url,
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
    cookieNames: (h.getSetCookie?.() ?? [])
      .map((c) => c.split('=')[0].trim())
      .filter(Boolean)
      .slice(0, 12),
  };
}

/** Pull identity and ownership signals out of the page source. */
function describePage(html, domain) {
  const head = html.slice(0, 150_000);

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

  // Service and analytics IDs are among the strongest ownership pivots
  // available: the same measurement ID, Sentry project or Firebase project on
  // two sites is good evidence of a common operator. Searchable on publicwww,
  // SpyOnWeb and Analyzeid.
  const trackers = [
    ...[...html.matchAll(/\b(G-[A-Z0-9]{6,12})\b/g)].map((m) => ({ type: 'Google Analytics 4', id: m[1] })),
    ...[...html.matchAll(/\b(UA-\d{4,10}-\d{1,4})\b/g)].map((m) => ({ type: 'Google Analytics (legacy)', id: m[1] })),
    ...[...html.matchAll(/\b(GTM-[A-Z0-9]{4,10})\b/g)].map((m) => ({ type: 'Google Tag Manager', id: m[1] })),
    ...[...html.matchAll(/\b(AW-\d{9,12})\b/g)].map((m) => ({ type: 'Google Ads', id: m[1] })),
    ...[...html.matchAll(/\b(ca-pub-\d{10,20})\b/g)].map((m) => ({ type: 'Google AdSense', id: m[1] })),
    ...[...html.matchAll(/fbq\(\s*['"]init['"]\s*,\s*['"](\d{8,20})['"]/g)].map((m) => ({ type: 'Meta Pixel', id: m[1] })),
    ...[...html.matchAll(/hjid\s*:\s*(\d{5,10})/g)].map((m) => ({ type: 'Hotjar', id: m[1] })),
    ...[...html.matchAll(/\bportalId["'\s:]+["']?(\d{5,10})/g)].map((m) => ({ type: 'HubSpot portal', id: m[1] })),
    ...[...html.matchAll(/app_id["'\s:]+["']([a-z0-9]{6,10})["']/gi)].map((m) => ({ type: 'Intercom app', id: m[1] })),
    ...[...html.matchAll(/https:\/\/[a-f0-9]{8,32}@(?:[a-z0-9.-]*\.)?(?:ingest\.)?sentry\.io\/(\d{4,12})/gi)].map((m) => ({ type: 'Sentry project', id: m[1] })),
    ...[...html.matchAll(/projectId["'\s:]+["']([a-z0-9-]{4,40})["']/gi)].map((m) => ({ type: 'Firebase project', id: m[1] })),
    ...[...html.matchAll(/\b(pk_live_[A-Za-z0-9]{10,50})\b/g)].map((m) => ({ type: 'Stripe publishable key', id: m[1] })),
    ...[...html.matchAll(/cdn\.segment\.(?:com|io)\/analytics\.js\/v1\/([A-Za-z0-9]{10,40})\//g)].map((m) => ({ type: 'Segment write key', id: m[1] })),
    ...[...html.matchAll(/\bUA_ID|_paq\.push\(\['setSiteId',\s*['"](\d{1,6})['"]/g)].map((m) => ({ type: 'Matomo site', id: m[1] })),
  ];

  const seen = new Set();
  const trackingIds = trackers.filter((t) => t.id && !seen.has(t.id) && seen.add(t.id)).slice(0, 20);

  return {
    title: head.match(/<title[^>]*>([\s\S]{1,300}?)<\/title>/i)?.[1]?.replace(/\s+/g, ' ').trim() ?? null,
    description: meta('name', 'description'),
    siteName: meta('property', 'og:site_name') ?? meta('name', 'application-name'),
    ogTitle: meta('property', 'og:title'),
    ogUrl: meta('property', 'og:url'),
    author: meta('name', 'author'),
    publisher: meta('name', 'publisher'),
    // `generator` names the CMS or site builder outright.
    generator: meta('name', 'generator'),
    themeColor: meta('name', 'theme-color'),
    twitterSite: meta('name', 'twitter:site'),
    twitterCreator: meta('name', 'twitter:creator'),
    // App-store links tie a website to a named developer account.
    appleApp: meta('name', 'apple-itunes-app'),
    androidApp: meta('name', 'google-play-app'),
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
    ).slice(0, 12),
    // `tel:` links are published contact numbers, and feed straight into a
    // phone lookup.
    phones: unique(
      [...html.matchAll(/href\s*=\s*["']tel:([+0-9().\-\s]{6,24})["']/gi)]
        .map((m) => m[1].replace(/\s+/g, ' ').trim()),
    ).slice(0, 8),
    socialProfiles: socialProfilesIn(html, domain),
    trackingIds,
    structuredData: parseJsonLd(html),
  };
}

/**
 * Social profile links, reduced to actual accounts.
 *
 * The naive version of this — every URL on a social host — is close to useless
 * on a large site, because product and marketing links vastly outnumber profile
 * links, and on a social platform's own site every internal link matches. Three
 * rules fix it: keep only the first path segment (a handle is never nested),
 * drop the platform's own site when it is the domain under analysis, and reject
 * the reserved product paths that are not accounts.
 */
const NON_PROFILE_SEGMENTS = new Set([
  'about', 'home', 'help', 'search', 'explore', 'settings', 'login', 'signup',
  'features', 'pricing', 'marketplace', 'enterprise', 'security', 'legal',
  'privacy', 'terms', 'blog', 'news', 'watch', 'shorts', 'channel', 'playlist',
  'sharer', 'share', 'intent', 'hashtag', 'pages', 'groups', 'events', 'p',
  'i', 'reel', 'status', 'topics', 'trending', 'notifications', 'messages',
  'developers', 'business', 'ads', 'careers', 'jobs', 'download', 'apps',
  'why-github', 'mcp', 'sponsors', 'collections', 'trending', 'contact',
]);

function socialProfilesIn(html, domain) {
  const pattern = /https?:\/\/(?:www\.)?(twitter\.com|x\.com|linkedin\.com|github\.com|gitlab\.com|facebook\.com|instagram\.com|youtube\.com|tiktok\.com|reddit\.com|mastodon\.social|bsky\.app|t\.me|discord\.gg|medium\.com|threads\.net|vimeo\.com|twitch\.tv|patreon\.com|substack\.com)\/([A-Za-z0-9_.\-@]{2,40})/g;
  const apex = registrableDomain(domain.split('.'));
  const found = new Set();

  for (const match of html.matchAll(pattern)) {
    const host = match[1].toLowerCase();
    // On a platform's own site every internal link looks like a profile.
    if (registrableDomain(host.split('.')) === apex) continue;

    const handle = match[2].replace(/[/.]+$/, '');
    const bare = handle.replace(/^@/, '').toLowerCase();
    if (!bare || NON_PROFILE_SEGMENTS.has(bare)) continue;
    // File names, not handles.
    if (/\.(png|jpe?g|gif|svg|webp|ico|css|js|json|xml)$/i.test(bare)) continue;
    // LinkedIn nests real profiles one level down; keep those two forms only.
    if (host === 'linkedin.com' && !['company', 'in', 'school', 'showcase'].includes(bare)) continue;

    const rest = host === 'linkedin.com'
      ? html.slice(match.index).match(/^https?:\/\/(?:www\.)?linkedin\.com\/(?:company|in|school|showcase)\/([A-Za-z0-9_.-]{2,60})/)?.[1]
      : null;

    found.add(host === 'linkedin.com'
      ? (rest ? `https://linkedin.com/${bare}/${rest}` : null)
      : `https://${host}/${handle}`);
  }

  found.delete(null);
  return [...found].slice(0, 16);
}

/**
 * schema.org JSON-LD.
 *
 * When a site publishes an Organization or LocalBusiness block, it hands over
 * the legal name, street address, phone number, founding date and its own list
 * of official profiles — self-declared, structured, and far more reliable than
 * anything scraped out of prose. It is routinely present and almost never read.
 */
function parseJsonLd(html) {
  const blocks = [...html.matchAll(/<script[^>]+type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]{0,20000}?)<\/script>/gi)];
  const entities = [];

  for (const block of blocks.slice(0, 6)) {
    let parsed;
    try {
      parsed = JSON.parse(block[1].trim());
    } catch {
      continue; // Malformed JSON-LD is extremely common; skip it quietly.
    }

    // A block may be one object, an array, or a @graph wrapper.
    const candidates = []
      .concat(parsed)
      .flatMap((item) => (item && item['@graph'] ? item['@graph'] : item))
      .filter((item) => item && typeof item === 'object');

    for (const item of candidates) {
      const type = [].concat(item['@type'] ?? []).join(', ');
      if (!/Organization|Corporation|LocalBusiness|Person|NewsMediaOrganization|Store|Restaurant/i.test(type)) continue;

      const address = item.address ?? {};
      entities.push({
        type,
        name: item.name ?? item.legalName ?? null,
        legalName: item.legalName ?? null,
        url: item.url ?? null,
        email: item.email ?? null,
        telephone: item.telephone ?? [].concat(item.contactPoint ?? [])[0]?.telephone ?? null,
        address: [address.streetAddress, address.addressLocality, address.addressRegion,
          address.postalCode, address.addressCountry].filter((v) => typeof v === 'string').join(', ') || null,
        founder: [].concat(item.founder ?? []).map((f) => (typeof f === 'string' ? f : f?.name)).filter(Boolean),
        foundingDate: item.foundingDate ?? null,
        taxId: item.taxID ?? item.vatID ?? null,
        // `sameAs` is the operator's own list of its official profiles.
        sameAs: [].concat(item.sameAs ?? []).filter((v) => typeof v === 'string').slice(0, 12),
      });
    }
  }

  return entities.length ? entities.slice(0, 4) : null;
}

/**
 * Favicon hash.
 *
 * Shodan, Censys and FOFA all index the MurmurHash3 of a site's base64-encoded
 * favicon. Because operators almost never change the icon when they move or
 * rename infrastructure, searching that hash finds every other host serving the
 * same site — including the origin server sitting behind a CDN, which is
 * otherwise one of the hardest things to establish from outside.
 */
async function faviconFingerprint(domain) {
  const bytes = await getBytes(`https://${domain}/favicon.ico`, {
    source: `${domain}/favicon.ico`,
    timeout: 7000,
  });

  // An SPA that serves its shell for every path returns HTML here.
  if (!bytes.length || bytes.length > 400_000) throw new Error('No usable favicon at the conventional path');
  const head = new TextDecoder().decode(bytes.slice(0, 40)).toLowerCase();
  if (head.includes('<html') || head.includes('<!doctype')) {
    throw new Error('The favicon path returned HTML, not an icon');
  }

  const hash = faviconHash(bytes);
  return {
    hash,
    bytes: bytes.length,
    shodanQuery: `http.favicon.hash:${hash}`,
    shodanUrl: `https://www.shodan.io/search?query=${encodeURIComponent(`http.favicon.hash:${hash}`)}`,
    censysUrl: `https://search.censys.io/search?resource=hosts&q=${encodeURIComponent(`services.http.response.favicons.md5_hash:*`)}`,
    fofaQuery: `icon_hash="${hash}"`,
    note: 'Searching this hash finds every other host serving the same icon — the standard way to locate an origin server behind a CDN.',
  };
}

/**
 * Files the site publishes at conventional public paths.
 *
 * Nothing here is a probe for something hidden: every path is a documented
 * convention that the operator publishes deliberately. `robots.txt` names the
 * paths they would rather crawlers avoided — which is where the interesting
 * parts of a site usually are — and `ads.txt` lists the ad-network publisher
 * accounts a site sells through, so the same account ID on another site is a
 * direct, hard link between the two.
 */
async function wellKnownFiles(domain, deep) {
  const wanted = deep ? WELL_KNOWN_FILES : WELL_KNOWN_FILES.slice(0, 2);

  const settled = await Promise.allSettled(
    wanted.map((file) =>
      getText(`https://${domain}${file.path}`, { source: `${domain}${file.path}`, timeout: 6000 })),
  );

  const files = [];
  settled.forEach((outcome, i) => {
    if (outcome.status !== 'fulfilled') return;
    const text = outcome.value;
    // SPA shells answer every path with HTML; that is not a published file.
    if (/<html|<!doctype/i.test(text.slice(0, 200)) || text.length > 200_000) return;

    files.push({ ...wanted[i], bytes: text.length, ...summarizeFile(wanted[i].path, text) });
  });

  return { checked: wanted.length, files };
}

function summarizeFile(path, text) {
  if (path === '/robots.txt') {
    const disallowed = [...text.matchAll(/^\s*Disallow:\s*(\S+)/gim)].map((m) => m[1]);
    return {
      sitemaps: [...text.matchAll(/^\s*Sitemap:\s*(\S+)/gim)].map((m) => m[1]).slice(0, 8),
      // The paths an operator asks crawlers to skip are, reliably, the paths
      // they consider sensitive.
      disallowed: [...new Set(disallowed)].filter((p) => p !== '/').slice(0, 40),
      disallowedCount: new Set(disallowed).size,
      agents: [...new Set([...text.matchAll(/^\s*User-agent:\s*(\S+)/gim)].map((m) => m[1]))].slice(0, 12),
    };
  }

  if (path === '/ads.txt' || path === '/app-ads.txt') {
    const rows = text.split('\n')
      .map((line) => line.split('#')[0].trim())
      .filter((line) => line && line.includes(','))
      .map((line) => {
        const [exchange, publisherId, relationship] = line.split(',').map((f) => f.trim());
        return { exchange, publisherId, relationship: relationship ?? null };
      });
    return {
      sellers: rows.slice(0, 40),
      sellerCount: rows.length,
      // A DIRECT entry means the publisher account belongs to this site's
      // owner, which is what makes it usable as an ownership link.
      directAccounts: [...new Set(rows.filter((r) => /direct/i.test(r.relationship ?? ''))
        .map((r) => `${r.exchange}:${r.publisherId}`))].slice(0, 20),
    };
  }

  return { excerpt: text.slice(0, 600).trim() || null };
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
  if (headers.get('x-sucuri-id')) return 'Sucuri';
  if (headers.get('x-iinfo')) return 'Imperva';
  return null;
}

/**
 * urlscan.io scan history.
 *
 * Anyone can submit a URL to urlscan and the results are public, so for a
 * domain of any interest there is usually a trail: when it was last scanned,
 * what addresses it served from, and — most useful — the page title and
 * technologies at the time. The search endpoint needs no key.
 */
async function urlScan(domain) {
  const body = await getJson(
    `https://urlscan.io/api/v1/search/?q=domain%3A${encodeURIComponent(domain)}&size=10`,
    { source: 'urlscan.io', timeout: 8000 },
  );

  const results = (body.results ?? []).slice(0, 10).map((r) => ({
    url: r.page?.url ?? null,
    title: r.page?.title ?? null,
    scannedAt: r.task?.time ? r.task.time.slice(0, 10) : null,
    address: r.page?.ip ?? null,
    asn: r.page?.asn ?? null,
    server: r.page?.server ?? null,
    country: r.page?.country ?? null,
    tlsIssuer: r.page?.tlsIssuer ?? null,
    screenshot: r.screenshot ?? null,
    reportUrl: r.result ?? null,
  }));

  return {
    total: body.total ?? results.length,
    results,
    // Addresses urlscan actually observed serving the site, which can differ
    // from what it resolves to right now.
    observedAddresses: [...new Set(results.map((r) => r.address).filter(Boolean))],
    observedAsns: [...new Set(results.map((r) => r.asn).filter(Boolean))],
  };
}

/**
 * Lookalike domain detection.
 *
 * dnstwister generates the permutation set a phishing operator would work from
 * — bitsquats, homoglyphs, transpositions, TLD swaps. The permutations alone
 * are noise; what matters is which of them someone has actually registered, so
 * a bounded, prioritised subset is resolved over the DNS path we already use.
 *
 * The cap is deliberate. Resolving all ~300 candidates would cost more
 * subrequests than the whole rest of the report put together.
 */
async function lookalikes(domain, limit) {
  const hex = [...domain].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
  const body = await getJson(`https://dnstwister.report/api/fuzz/${hex}`, {
    source: 'dnstwister.report',
    timeout: 6000,
  });

  const candidates = (body.fuzzy_domains ?? [])
    .map((f) => ({ domain: f.domain, technique: f.fuzzer }))
    .filter((c) => c.domain && c.domain !== domain);

  // Techniques that produce the most convincing fakes go first, since only a
  // handful get resolved.
  const priority = ['Homoglyph', 'Transposition', 'Omission', 'Repetition', 'Replacement', 'Bitsquatting'];
  const ranked = candidates.slice().sort((a, b) => {
    const rank = (t) => {
      const i = priority.findIndex((p) => (t ?? '').toLowerCase().includes(p.toLowerCase()));
      return i === -1 ? priority.length : i;
    };
    return rank(a.technique) - rank(b.technique);
  });

  const checked = ranked.slice(0, limit);
  const settled = await Promise.allSettled(checked.map((c) => resolve(c.domain, 'A')));

  const registered = [];
  settled.forEach((outcome, i) => {
    if (outcome.status === 'fulfilled' && outcome.value.records.length) {
      registered.push({
        domain: checked[i].domain,
        technique: checked[i].technique,
        addresses: outcome.value.records,
      });
    }
  });

  return {
    generated: candidates.length,
    checked: checked.length,
    registered,
    // Be explicit that a clean result only covers what was actually tested.
    note: `${checked.length} of ${candidates.length} generated permutations were resolved.`,
  };
}

async function virusTotalDomain(domain, key) {
  const body = await getJson(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
    source: 'virustotal.com',
    headers: { 'x-apikey': key },
  });
  const attributes = body.data?.attributes ?? {};
  const stats = attributes.last_analysis_stats ?? {};
  return {
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    reputation: attributes.reputation ?? null,
    categories: Object.values(attributes.categories ?? {}).slice(0, 6),
    flaggedBy: Object.entries(attributes.last_analysis_results ?? {})
      .filter(([, result]) => result.category === 'malicious')
      .map(([vendor]) => vendor)
      .slice(0, 12),
  };
}

/**
 * Resolve discovered subdomains and read what the answers imply.
 *
 * Three findings come out of one batch of lookups:
 *
 *   - which CT names are live at all, since most are historical
 *   - which resolve *outside* the address set the apex uses, which on a
 *     CDN-fronted site is the classic origin-server exposure
 *   - which point at a SaaS platform via CNAME but no longer resolve to a live
 *     site there, the precondition for a subdomain takeover
 */
async function mapSubdomains(subdomains, domain, apexAddresses) {
  const candidates = subdomains.filter((name) => name !== domain);
  if (!candidates.length) return { checked: 0, live: [], groups: [], originCandidates: [], takeoverCandidates: [] };

  // Rank interesting prefixes first, then shortest — a two-label name is more
  // likely to be real infrastructure than a long generated one.
  const score = (name) => {
    const label = name.slice(0, name.length - domain.length - 1);
    const head = label.split('.').pop();
    const index = INTERESTING_PREFIXES.findIndex((p) => head === p || head.startsWith(p));
    return index === -1 ? 500 + label.length : index;
  };
  const chosen = candidates.slice().sort((a, b) => score(a) - score(b)).slice(0, 25);

  const results = await resolveBatch(chosen, 'A');
  const apexSet = new Set(apexAddresses);

  const live = [];
  const takeoverCandidates = [];

  for (const result of results) {
    const alias = result.aliases[result.aliases.length - 1] ?? null;

    if (result.records.length) {
      live.push({ name: result.name, addresses: result.records, cname: alias });
      continue;
    }

    // No address, but a CNAME into a known platform: the takeover shape.
    if (alias) {
      const signature = TAKEOVER_SIGNATURES.find((s) => s.cname.test(alias));
      if (signature) {
        takeoverCandidates.push({
          name: result.name,
          cname: alias,
          service: signature.service,
          status: result.status,
          note: 'The alias target does not resolve. If the platform account has been released, this name may be claimable by a third party. Confirm before acting on it.',
        });
      }
    }
  }

  // Group by address so shared infrastructure is obvious at a glance.
  const byAddress = new Map();
  for (const entry of live) {
    for (const address of entry.addresses) {
      if (!byAddress.has(address)) byAddress.set(address, []);
      byAddress.get(address).push(entry.name);
    }
  }

  const groups = [...byAddress.entries()]
    .map(([address, names]) => ({ address, names, count: names.length }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 15);

  // Addresses used by a subdomain but not by the apex. When the apex is behind
  // a CDN, these are the un-fronted hosts.
  const originCandidates = groups
    .filter((group) => !apexSet.has(group.address))
    .slice(0, 10);

  return {
    discovered: candidates.length,
    checked: chosen.length,
    live,
    groups,
    originCandidates,
    takeoverCandidates,
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
        hostnames: e?.hostnames ?? [],
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

/**
 * Who actually runs each piece of this domain's infrastructure.
 *
 * The individual records are already in the report; what an investigator wants
 * from them is one line per function — mail here, DNS there, edge somewhere
 * else — because that is the shape that tells you which organisations to go and
 * ask, and which of them would hold logs.
 */
function identifyProviders(data) {
  const mx = (data.dns?.MX?.records ?? []).map((r) => r.split(/\s+/).pop());
  const ns = data.dns?.NS?.records ?? data.registration?.nameservers ?? [];

  return {
    mail: mailProvider(...mx),
    mailServers: mx.slice(0, 8),
    dns: dnsProvider(...ns),
    nameservers: ns.slice(0, 8),
    cdn: data.headers?.cdn ?? null,
    registrar: data.registration?.registrar ?? null,
    // A DMARC reporting address at a vendor's domain names the vendor.
    dmarcReporting: data.email?.dmarc?.reportingDomains ?? [],
    // DKIM selectors are the most complete list of sending platforms available.
    sendingPlatforms: (data.dkim?.platforms ?? []).filter((p) => p !== 'generic'),
  };
}

/** Consolidate the DNSSEC signals, which are spread across three records. */
function dnssecPosture(data) {
  const ds = data.dns?.DS?.records ?? [];
  const dnskey = data.dnskey?.records ?? [];
  const delegated = data.registration?.dnssec;

  return {
    delegationSigned: delegated ?? (ds.length > 0 ? true : null),
    dsRecords: ds.length,
    dnskeyRecords: dnskey.length || null,
    // A zone with keys but no DS at the parent is signed but not trusted —
    // a misconfiguration that looks like DNSSEC without providing it.
    signedButNotDelegated: dnskey.length > 0 && ds.length === 0,
    algorithms: [...new Set(ds.map((r) => r.split(/\s+/)[1]).filter(Boolean))],
  };
}

/* ------------------------------------------------------------------ identity */

/**
 * Consolidate every attribution signal into one ranked view.
 *
 * RDAP registrant data is redacted for most gTLDs post-GDPR, so the answer to
 * "who runs this domain" usually has to be assembled from what the operator
 * publishes voluntarily: structured data, the site's own metadata, its
 * copyright line, its security.txt contact. Each candidate carries the source
 * it came from and how far it can be trusted, because these differ enormously —
 * a registry registrant field is authoritative, a copyright string is a guess.
 */
function identity(data) {
  const page = data.headers?.page ?? null;
  const reg = data.registration ?? null;
  const names = [];

  const add = (value, source, confidence) => {
    if (!value) return;
    const clean = String(value).trim();
    if (clean.length < 2 || clean.length > 120) return;
    const existing = names.find((n) => n.value.toLowerCase() === clean.toLowerCase());
    if (existing) {
      existing.corroboration = (existing.corroboration ?? 1) + 1;
      return;
    }
    names.push({ value: clean, source, confidence, corroboration: 1 });
  };

  // Authoritative when present — but usually redacted.
  if (reg?.registrant && !reg.registrant.redacted) {
    add(reg.registrant.organization ?? reg.registrant.name, 'RDAP registrant', 'high');
  }
  if (reg?.administrative && !reg.administrative.redacted) {
    add(reg.administrative.organization ?? reg.administrative.name, 'RDAP admin contact', 'high');
  }

  // Self-declared and structured: the operator wrote it, in a machine-readable
  // field whose whole purpose is to state the legal entity.
  for (const entity of page?.structuredData ?? []) {
    add(entity.legalName, 'schema.org legalName', 'high');
    add(entity.name, 'schema.org name', 'medium');
  }

  // Self-declared prose. Generally accurate, but not a legal name.
  add(page?.siteName, 'og:site_name', 'medium');
  page?.copyright?.forEach((c) => add(c, 'copyright notice', 'medium'));
  add(page?.author, 'author meta tag', 'medium');
  add(page?.publisher, 'publisher meta tag', 'medium');

  // Weakest: a title is marketing copy, not a legal entity.
  add(page?.title?.split(/\s[|·—–-]\s/)[0], 'page title', 'low');

  const contacts = [];
  for (const contact of data.securityTxt?.contacts ?? []) {
    contacts.push({ value: contact.replace(/^mailto:/, ''), source: 'security.txt', role: 'security' });
  }
  if (reg?.abuseContact?.email) {
    contacts.push({ value: reg.abuseContact.email, source: 'RDAP registrar abuse', role: 'abuse' });
  }
  for (const entity of page?.structuredData ?? []) {
    if (entity.email) contacts.push({ value: entity.email, source: 'schema.org', role: 'published' });
    if (entity.telephone) contacts.push({ value: entity.telephone, source: 'schema.org', role: 'phone' });
    if (entity.address) contacts.push({ value: entity.address, source: 'schema.org', role: 'address' });
  }
  for (const email of page?.emails ?? []) {
    contacts.push({ value: email, source: 'page source', role: 'published' });
  }
  for (const phone of page?.phones ?? []) {
    contacts.push({ value: phone, source: 'tel: link', role: 'phone' });
  }

  const rank = { high: 0, medium: 1, low: 2 };
  names.sort((a, b) => rank[a.confidence] - rank[b.confidence] || b.corroboration - a.corroboration);

  // `sameAs` is the operator's own declaration of which profiles are theirs,
  // which is worth more than a link found somewhere in the page body.
  const declaredProfiles = (page?.structuredData ?? []).flatMap((e) => e.sameAs ?? []);

  return {
    names,
    best: names[0] ?? null,
    contacts: dedupe(contacts, (c) => `${c.role}:${c.value.toLowerCase()}`).slice(0, 16),
    socialProfiles: [...new Set([...declaredProfiles, ...(page?.socialProfiles ?? [])])].slice(0, 16),
    declaredProfiles,
    trackingIds: page?.trackingIds ?? [],
    // Say plainly why the registrant is missing, rather than showing a blank.
    registrantStatus: reg?.registrant?.redacted
      ? 'redacted'
      : reg?.registrant
        ? 'published'
        : 'not published',
  };
}

function dedupe(items, key) {
  const seen = new Set();
  return items.filter((item) => {
    const k = key(item);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/* --------------------------------------------------------------- assessment */

function assess(domain, data, hosts, subdomainDetail) {
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

  if (data.dnssec?.signedButNotDelegated) {
    findings.push({
      level: 'warn',
      title: 'Zone is signed but the delegation is not',
      detail: 'DNSKEY records exist but no DS record is published at the parent, so resolvers cannot validate the signatures. This provides the cost of DNSSEC with none of the protection.',
    });
  } else if (reg && reg.dnssec === false) {
    findings.push({ level: 'info', title: 'DNSSEC not enabled', detail: 'Responses for this zone are not cryptographically signed.' });
  }

  if (data.wildcard?.wildcard) {
    findings.push({
      level: 'info',
      title: 'Wildcard DNS is enabled',
      detail: `A random name (${data.wildcard.probe}) resolved to ${data.wildcard.addresses.join(', ')}. Every subdomain "exists" on this zone, so resolution proves nothing about whether a name was deliberately configured.`,
    });
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

  if (data.dkim?.found?.length) {
    const platforms = [...new Set(data.dkim.found.map((f) => f.platform).filter((p) => p !== 'generic'))];
    findings.push({
      level: 'info',
      title: `${data.dkim.found.length} DKIM selector(s) published`,
      detail: (platforms.length
        ? `Sending platforms in use: ${platforms.join(', ')}. `
        : '')
        + 'Each selector is a service authorised to send mail as this domain, and several appear nowhere else in DNS.',
    });
    const weak = data.dkim.found.filter((f) => f.keyBits && f.keyBits < 1024);
    if (weak.length) {
      findings.push({
        level: 'warn',
        title: `${weak.length} DKIM key(s) shorter than 1024 bits`,
        detail: `Selectors: ${weak.map((w) => w.selector).join(', ')}. Keys this short are considered forgeable and some receivers ignore them entirely.`,
      });
    }
  }

  if (data.srv?.found?.length) {
    findings.push({
      level: 'info',
      title: `${data.srv.found.length} SRV service record(s)`,
      detail: data.srv.found.slice(0, 6).map((s) => `${s.service} → ${s.target}:${s.port}`).join(' · ')
        + '. SRV targets name internal hosts that A records for the apex never expose.',
    });
  }

  if (!(data.dns?.CAA?.records ?? []).length) {
    findings.push({ level: 'info', title: 'No CAA record', detail: 'Any certificate authority may issue certificates for this domain.' });
  }

  const takeovers = subdomainDetail?.takeoverCandidates ?? [];
  if (takeovers.length) {
    findings.push({
      level: 'danger',
      title: `${takeovers.length} possible subdomain takeover${takeovers.length === 1 ? '' : 's'}`,
      detail: takeovers.map((t) => `${t.name} → ${t.cname} (${t.service})`).join(' · ')
        + '. Each of these points at a platform where the target no longer resolves. Verify the account is genuinely unclaimed before treating this as confirmed.',
    });
  }

  const origins = subdomainDetail?.originCandidates ?? [];
  if (origins.length && data.headers?.cdn) {
    findings.push({
      level: 'warn',
      title: `${origins.length} subdomain address${origins.length === 1 ? '' : 'es'} outside the CDN`,
      detail: origins.slice(0, 5).map((o) => `${o.address} (${o.names.slice(0, 3).join(', ')})`).join(' · ')
        + `. The apex is fronted by ${data.headers.cdn}, but these names resolve directly. Addresses like these are how a CDN's protection gets bypassed.`,
    });
  }

  const headers = data.headers;
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
    if (headers.chain?.length > 1) {
      const hops = headers.chain.map((h) => h.url);
      const offsite = hops.filter((url) => {
        try { return !new URL(url).hostname.endsWith(domain.split('.').slice(-2).join('.')); } catch { return false; }
      });
      if (offsite.length) {
        findings.push({
          level: 'warn',
          title: 'Redirects off-site before serving content',
          detail: `Route: ${hops.join(' → ')}. A redirect to a different registrable domain is worth explaining — it is the shape of an affiliate hop, a parked domain, or a hijack.`,
        });
      }
    }
  }

  if (data.technologies?.length) {
    const categories = [...new Set(data.technologies.map((t) => t.category))];
    findings.push({
      level: 'info',
      title: `${data.technologies.length} technologies fingerprinted`,
      detail: `${categories.join(', ')}. Detected from response headers, cookie names and page source — no probing.`,
    });
  }

  if (data.favicon?.hash) {
    findings.push({
      level: 'info',
      title: `Favicon hash ${data.favicon.hash}`,
      detail: 'Searching this hash on Shodan or FOFA returns every other host serving the same icon. It is the standard way to find an origin server behind a CDN, and to link sites that share a template.',
    });
  }

  const publicFiles = data.publicFiles?.files ?? [];
  const robots = publicFiles.find((f) => f.path === '/robots.txt');
  if (robots?.disallowedCount) {
    findings.push({
      level: 'info',
      title: `robots.txt lists ${robots.disallowedCount} disallowed path(s)`,
      detail: `${robots.disallowed.slice(0, 8).join(', ')}${robots.disallowedCount > 8 ? ', …' : ''}. Paths an operator asks crawlers to avoid are, reliably, the ones they consider sensitive.`,
    });
  }
  const ads = publicFiles.find((f) => f.path === '/ads.txt' && f.directAccounts?.length);
  if (ads) {
    findings.push({
      level: 'info',
      title: `ads.txt declares ${ads.directAccounts.length} direct seller account(s)`,
      detail: `${ads.directAccounts.slice(0, 5).join(', ')}. A DIRECT account belongs to this site's owner, so the same ID on another site is a hard ownership link between them.`,
    });
  }

  if (data.certificates?.relatedDomains?.length) {
    findings.push({
      level: 'info',
      title: `${data.certificates.relatedDomains.length} other domain(s) share a certificate with this one`,
      detail: `${data.certificates.relatedDomains.slice(0, 8).join(', ')}${data.certificates.relatedDomains.length > 8 ? ', …' : ''}. A certificate covering two domains was issued to whoever proved control of both.`,
    });
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

  const impostors = data.lookalikes?.registered ?? [];
  if (impostors.length) {
    findings.push({
      level: 'warn',
      title: `${impostors.length} lookalike domain${impostors.length === 1 ? '' : 's'} registered`,
      detail: impostors.slice(0, 5).map((i) => `${i.domain} (${i.technique})`).join(', ')
        + `. ${data.lookalikes.note} Registration alone is not proof of abuse, but these are the names a phishing operator would use.`,
    });
  }

  const identified = data.headers?.page;
  if (identified?.trackingIds?.length) {
    findings.push({
      level: 'info',
      title: `${identified.trackingIds.length} service ID${identified.trackingIds.length === 1 ? '' : 's'} in the page source`,
      detail: identified.trackingIds.slice(0, 5).map((t) => `${t.id} (${t.type})`).join(', ')
        + '. The same ID appearing on another site is good evidence of a shared operator. Searchable on publicwww.com and analyzeid.com.',
    });
  }

  if (identified?.structuredData?.length) {
    const entity = identified.structuredData[0];
    findings.push({
      level: 'ok',
      title: `Site publishes structured data for ${entity.legalName ?? entity.name ?? 'an organisation'}`,
      detail: [entity.type, entity.address, entity.telephone, entity.foundingDate ? `founded ${entity.foundingDate}` : null]
        .filter(Boolean).join(' · ')
        + '. Self-declared schema.org data is the operator naming themselves in a machine-readable field.',
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
    findings.push({
      level: 'info',
      title: `${subCount} subdomain${subCount === 1 ? '' : 's'} in Certificate Transparency`,
      detail: subdomainDetail
        ? `${subdomainDetail.live.length} of the ${subdomainDetail.checked} most interesting names still resolve.`
        : 'Names observed in publicly-logged certificates. Some may no longer resolve — run a deep scan to check which.',
    });
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

function pivots(domain, favicon) {
  const links = [
    { label: 'crt.sh', url: `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}` },
    { label: 'VirusTotal', url: `https://www.virustotal.com/gui/domain/${domain}` },
    { label: 'urlscan.io', url: `https://urlscan.io/domain/${domain}` },
    { label: 'Wayback Machine', url: `https://web.archive.org/web/*/${domain}` },
    { label: 'Shodan', url: `https://www.shodan.io/search?query=hostname%3A${encodeURIComponent(domain)}` },
    { label: 'SecurityTrails', url: `https://securitytrails.com/domain/${domain}/dns` },
    { label: 'BuiltWith', url: `https://builtwith.com/${domain}` },
    { label: 'ViewDNS history', url: `https://viewdns.info/iphistory/?domain=${domain}` },
    { label: 'DNSlytics', url: `https://dnslytics.com/domain/${domain}` },
    { label: 'Netcraft', url: `https://sitereport.netcraft.com/?url=https://${domain}` },
    { label: 'PublicWWW', url: `https://publicwww.com/websites/%22${encodeURIComponent(domain)}%22/` },
    { label: 'Google site:', url: `https://www.google.com/search?q=${encodeURIComponent(`site:${domain}`)}` },
    { label: 'Google related docs', url: `https://www.google.com/search?q=${encodeURIComponent(`site:${domain} (filetype:pdf OR filetype:xlsx OR filetype:docx)`)}` },
  ];
  if (favicon?.hash != null) {
    links.push({ label: `Shodan favicon ${favicon.hash}`, url: favicon.shodanUrl });
  }
  return links;
}
