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

/** One plain HTTPS GET to read the domain's security header posture. */
async function securityHeaders(domain) {
  const response = await request(`https://${domain}/`, {
    source: domain,
    timeout: 8000,
    headers: { accept: 'text/html,*/*' },
  });

  const h = response.headers;
  const present = (name) => h.get(name) ?? null;

  return {
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
