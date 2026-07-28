/**
 * IP address reconnaissance.
 *
 * GhostTrack's original IP tracker was a single call to ipwho.is printed to a
 * terminal. This keeps that geolocation but adds the parts that actually matter
 * for an investigation: who owns the netblock (RDAP), what the IP calls itself
 * (PTR), what it exposes (Shodan InternetDB), and whether it looks like
 * infrastructure rather than a person (hosting/proxy signals).
 */

import { getJson, getText, gather } from '../lib/http.js';
import { reverseLookup } from '../lib/dns.js';
import { parseIp } from '../lib/validate.js';
import * as rdap from '../lib/rdap.js';

export async function lookupIp(input, env = {}) {
  const ip = parseIp(input);

  // Non-routable addresses have no registry, no geolocation and no exposure.
  // Say so plainly rather than shipping four confusing upstream errors.
  if (ip.scope !== 'public') {
    return {
      query: { type: 'ip', value: ip.value, version: ip.version },
      routable: false,
      scope: ip.scope,
      summary: `${ip.value} is a ${describeScope(ip.scope)} address. It is not routable on the public internet, so there is nothing to enumerate.`,
      sources: {},
    };
  }

  const { data, sources } = await gather({
    geo: () => geolocate(ip.value),
    registry: () => registryInfo(ip.value),
    ptr: () => reverseLookup(ip.value, ip.version),
    exposure: () => shodanInternetDb(ip.value),
    routing: () => routing(ip.value),
    neighbours: () => reverseIp(ip.value),
    ...(env.ABUSEIPDB_API_KEY ? { abuse: () => abuseIpDb(ip.value, env.ABUSEIPDB_API_KEY) } : {}),
    ...(env.VIRUSTOTAL_API_KEY ? { reputation: () => virusTotalIp(ip.value, env.VIRUSTOTAL_API_KEY) } : {}),
  });

  return {
    query: { type: 'ip', value: ip.value, version: ip.version },
    routable: true,
    scope: ip.scope,
    geolocation: data.geo,
    registry: data.registry,
    reverseDns: data.ptr,
    routing: data.routing,
    hostedDomains: data.neighbours,
    exposure: data.exposure,
    abuse: data.abuse ?? null,
    reputation: data.reputation ?? null,
    assessment: assess(data),
    pivots: pivots(ip.value),
    sources,
  };
}

function describeScope(scope) {
  return {
    private: 'private (RFC 1918)',
    loopback: 'loopback',
    'link-local': 'link-local',
    cgnat: 'carrier-grade NAT (RFC 6598)',
    reserved: 'reserved',
  }[scope] ?? scope;
}

/* ------------------------------------------------------------------ sources */

/**
 * Geolocation, across several providers.
 *
 * Free geo-IP APIs meter by source address. On Workers the source address is
 * Cloudflare's shared egress, so a per-IP monthly quota is routinely spent by
 * unrelated traffic before our request arrives — ipwho.is returns 429 more
 * often than not. Rather than let that blank the panel, providers are tried in
 * order of detail and the first success wins, with the provider recorded so the
 * report says where the answer came from.
 */
async function geolocate(ip) {
  const providers = [ipwhois, ipApi, ripeStatGeo];
  let lastError;

  for (const provider of providers) {
    try {
      return await provider(ip);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError ?? new Error('No geolocation provider responded');
}

/** RIPE NCC's own geolocation. Country-level only, but effectively unmetered. */
async function ripeStatGeo(ip) {
  const body = await getJson(
    `https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${encodeURIComponent(ip)}`,
    { source: 'stat.ripe.net', timeout: 9000 },
  );

  const location = body.data?.located_resources?.[0]?.locations?.[0];
  if (!location?.country) throw new Error('RIPEstat has no geolocation for this address');

  return {
    provider: 'stat.ripe.net',
    country: location.country,
    countryCode: location.country,
    flag: null,
    region: null,
    city: location.city || null,
    postal: null,
    continent: null,
    latitude: location.latitude ?? null,
    longitude: location.longitude ?? null,
    // Coordinates here are a country centroid, not a place. Say so.
    precision: location.city ? 'city' : 'country',
    timezone: null,
    isp: null,
    organization: null,
    asn: null,
    asnDomain: null,
    callingCode: null,
    isEu: null,
    mapUrl: null,
  };
}

/** ip-api.com. City-level; free tier is HTTP-only and rate-limited per minute. */
async function ipApi(ip) {
  const body = await getJson(
    `http://ip-api.com/json/${encodeURIComponent(ip)}` +
      '?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as',
    { source: 'ip-api.com', timeout: 8000 },
  );
  if (body.status !== 'success') {
    throw new Error(`ip-api.com could not resolve ${ip}: ${body.message ?? 'no detail given'}`);
  }

  return {
    provider: 'ip-api.com',
    country: body.country ?? null,
    countryCode: body.countryCode ?? null,
    flag: null,
    region: body.regionName ?? null,
    city: body.city ?? null,
    postal: body.zip ?? null,
    continent: null,
    latitude: body.lat ?? null,
    longitude: body.lon ?? null,
    precision: body.city ? 'city' : body.regionName ? 'region' : 'country',
    timezone: body.timezone ? { id: body.timezone, utcOffset: null, abbreviation: null } : null,
    isp: body.isp ?? null,
    organization: body.org ?? body.isp ?? null,
    asn: body.as ? body.as.split(' ')[0] : null,
    asnDomain: null,
    callingCode: null,
    isEu: null,
    mapUrl: body.lat != null
      ? `https://www.openstreetmap.org/?mlat=${body.lat}&mlon=${body.lon}#map=11/${body.lat}/${body.lon}`
      : null,
  };
}

/** ipwho.is. The richest free payload, and the first to run out of quota. */
async function ipwhois(ip) {
  const body = await getJson(`https://ipwho.is/${encodeURIComponent(ip)}`, {
    source: 'ipwho.is',
    timeout: 8000,
  });
  if (body.success === false) {
    throw new Error(`ipwho.is could not resolve ${ip}: ${body.message ?? 'no detail given'}`);
  }

  return {
    provider: 'ipwho.is',
    country: body.country ?? null,
    countryCode: body.country_code ?? null,
    flag: body.flag?.emoji ?? null,
    region: body.region ?? null,
    city: body.city ?? null,
    postal: body.postal ?? null,
    continent: body.continent ?? null,
    latitude: body.latitude ?? null,
    longitude: body.longitude ?? null,
    // Free geo-IP is city-accurate at best, and often only country-accurate.
    // Label the precision so nobody treats these coordinates as a street address.
    precision: body.city ? 'city' : body.region ? 'region' : 'country',
    timezone: body.timezone
      ? { id: body.timezone.id, utcOffset: body.timezone.utc, abbreviation: body.timezone.abbr }
      : null,
    isp: body.connection?.isp ?? null,
    organization: body.connection?.org ?? null,
    asn: body.connection?.asn ? `AS${body.connection.asn}` : null,
    asnDomain: body.connection?.domain ?? null,
    callingCode: body.calling_code ? `+${body.calling_code}` : null,
    isEu: body.is_eu ?? null,
    mapUrl:
      body.latitude != null && body.longitude != null
        ? `https://www.openstreetmap.org/?mlat=${body.latitude}&mlon=${body.longitude}#map=11/${body.latitude}/${body.longitude}`
        : null,
  };
}

async function registryInfo(ip) {
  const body = await rdap.lookup('ip', ip);
  const roles = rdap.entitiesByRole(body.entities);

  return {
    handle: body.handle ?? null,
    name: body.name ?? null,
    range: body.startAddress && body.endAddress ? `${body.startAddress} – ${body.endAddress}` : null,
    cidr: (body.cidr0_cidrs ?? [])
      .map((c) => `${c.v4prefix ?? c.v6prefix}/${c.length}`)
      .join(', ') || null,
    type: body.type ?? null,
    country: body.country ?? null,
    registry: (body.port43 ?? '').replace(/^whois\./, '') || null,
    registered: rdap.eventDate(body.events, 'registration'),
    updated: rdap.eventDate(body.events, 'last changed'),
    status: body.status ?? [],
    registrant: roles.registrant ?? roles.administrative ?? null,
    abuseContact: roles.abuse ?? null,
    // The parent allocation, when the registry exposes one.
    parent: body.parentHandle ?? null,
  };
}

/**
 * Shodan's InternetDB is the free, keyless slice of their dataset: open ports,
 * detected CVEs, known hostnames and software CPEs. A 404 means Shodan has
 * simply never seen the host, which is a meaningful (clean) result rather than
 * an error.
 */
async function shodanInternetDb(ip) {
  try {
    const body = await getJson(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
      source: 'internetdb.shodan.io',
      timeout: 8000,
    });
    return {
      seen: true,
      ports: body.ports ?? [],
      vulnerabilities: body.vulns ?? [],
      hostnames: body.hostnames ?? [],
      software: body.cpes ?? [],
      tags: body.tags ?? [],
    };
  } catch (err) {
    if (err.status === 404) {
      return { seen: false, ports: [], vulnerabilities: [], hostnames: [], software: [], tags: [] };
    }
    throw err;
  }
}

/**
 * BGP routing view from RIPEstat.
 *
 * Geolocation says where a database claims the address is; routing says who
 * actually announces it to the internet, which is the harder fact to fake and
 * the better basis for attribution.
 */
async function routing(ip) {
  const body = await getJson(
    `https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`,
    { source: 'stat.ripe.net', timeout: 10000 },
  );

  const d = body.data ?? {};
  const asns = (d.asns ?? []).map((a) => ({ asn: `AS${a.asn}`, holder: a.holder ?? null }));

  return {
    announcedPrefix: d.resource ?? null,
    announced: d.announced ?? null,
    originAsns: asns,
    // Registry-level block metadata, when RIPEstat has it.
    blockDescription: d.block?.desc ?? null,
    blockName: d.block?.name ?? null,
    relatedPrefixes: (d.related_prefixes ?? []).slice(0, 8),
  };
}

/**
 * Other domains resolving to the same address.
 *
 * On dedicated hosting this names the operator directly. On shared hosting or
 * behind a CDN it says only that the address is shared — which is itself worth
 * knowing, because it means the address does not identify one owner.
 */
async function reverseIp(ip) {
  // HackerTarget meters ~50 requests per day per source address, which on
  // Cloudflare's shared egress is permanently exhausted. RapidDNS has no such
  // quota, so it leads and HackerTarget is the fallback.
  const providers = [rapidDns, hackerTargetReverse];
  let lastError;

  for (const provider of providers) {
    try {
      const domains = await provider(ip);
      return {
        provider: provider.sourceName,
        count: domains.length,
        domains: domains.slice(0, 100),
        truncated: domains.length > 100,
        // Many unrelated names on one address means shared infrastructure.
        shared: domains.length > 5,
      };
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError ?? new Error('No reverse-IP provider responded');
}

/** RapidDNS returns an HTML table; the hostnames sit in its cells. */
async function rapidDns(ip) {
  const text = await getText(`https://rapiddns.io/sameip/${encodeURIComponent(ip)}?full=1`, {
    source: 'rapiddns.io',
    timeout: 10000,
  });

  const domains = [...text.matchAll(/<td>\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\s*<\/td>/gi)]
    .map((m) => m[1].toLowerCase());
  if (!domains.length && !/no results|not found/i.test(text)) {
    throw new Error('rapiddns.io returned no parseable rows');
  }
  return [...new Set(domains)];
}
rapidDns.sourceName = 'rapiddns.io';

async function hackerTargetReverse(ip) {
  const text = await getText(
    `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`,
    { source: 'hackertarget.com', timeout: 9000 },
  );

  if (/no records/i.test(text)) return [];
  if (/API count exceeded|error/i.test(text)) {
    throw new Error('HackerTarget quota exceeded for this source address');
  }

  return [...new Set(
    text.split('\n').map((line) => line.trim().toLowerCase()).filter((d) => d && d.includes('.')),
  )];
}
hackerTargetReverse.sourceName = 'hackertarget.com';

async function abuseIpDb(ip, key) {
  const body = await getJson(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
    { source: 'abuseipdb.com', headers: { Key: key, Accept: 'application/json' } },
  );
  const d = body.data ?? {};
  return {
    confidenceScore: d.abuseConfidenceScore ?? null,
    totalReports: d.totalReports ?? 0,
    distinctReporters: d.numDistinctUsers ?? 0,
    lastReportedAt: d.lastReportedAt ?? null,
    usageType: d.usageType ?? null,
    isTor: d.isTor ?? null,
    isWhitelisted: d.isWhitelisted ?? null,
  };
}

async function virusTotalIp(ip, key) {
  const body = await getJson(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
    source: 'virustotal.com',
    headers: { 'x-apikey': key },
  });
  const stats = body.data?.attributes?.last_analysis_stats ?? {};
  return {
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    undetected: stats.undetected ?? 0,
    reputation: body.data?.attributes?.reputation ?? null,
  };
}

/* --------------------------------------------------------------- assessment */

/**
 * Turn the raw signals into a short list of plain-language findings, so the
 * report leads with meaning instead of with JSON.
 */
function assess(data) {
  const findings = [];
  const org = `${data.geo?.organization ?? ''} ${data.geo?.isp ?? ''} ${data.registry?.name ?? ''}`.toLowerCase();
  const ptr = (data.ptr ?? '').toLowerCase();

  const HOSTING = ['amazon', 'aws', 'google', 'microsoft', 'azure', 'digitalocean', 'linode',
    'akamai', 'cloudflare', 'fastly', 'ovh', 'hetzner', 'vultr', 'oracle', 'contabo', 'leaseweb'];
  const hostingHit = HOSTING.find((h) => org.includes(h) || ptr.includes(h));
  if (hostingHit) {
    findings.push({
      level: 'info',
      title: 'Hosting or CDN infrastructure',
      detail: `Owned by ${data.geo?.organization ?? data.registry?.name}. Geolocation reflects the datacenter, not a user — treat the coordinates as meaningless for attribution.`,
    });
  }

  if (data.abuse?.confidenceScore >= 50) {
    findings.push({
      level: 'danger',
      title: `Abuse confidence ${data.abuse.confidenceScore}%`,
      detail: `${data.abuse.totalReports} reports from ${data.abuse.distinctReporters} distinct reporters in the last 90 days.`,
    });
  } else if (data.abuse?.totalReports > 0) {
    findings.push({
      level: 'warn',
      title: 'Previously reported for abuse',
      detail: `${data.abuse.totalReports} report(s) in the last 90 days, but confidence is low (${data.abuse.confidenceScore}%).`,
    });
  }

  if (data.abuse?.isTor) {
    findings.push({ level: 'warn', title: 'Tor exit node', detail: 'Traffic from this address is anonymized; it does not identify an end user.' });
  }

  const vulnCount = data.exposure?.vulnerabilities?.length ?? 0;
  if (vulnCount) {
    findings.push({
      level: 'danger',
      title: `${vulnCount} known CVE${vulnCount === 1 ? '' : 's'} detected`,
      detail: data.exposure.vulnerabilities.slice(0, 8).join(', ') + (vulnCount > 8 ? ', …' : ''),
    });
  }

  const ports = data.exposure?.ports ?? [];
  const RISKY = { 21: 'FTP', 23: 'Telnet', 135: 'MSRPC', 445: 'SMB', 3389: 'RDP', 5900: 'VNC', 27017: 'MongoDB', 6379: 'Redis', 9200: 'Elasticsearch', 3306: 'MySQL', 5432: 'PostgreSQL' };
  const risky = ports.filter((p) => RISKY[p]).map((p) => `${p}/${RISKY[p]}`);
  if (risky.length) {
    findings.push({
      level: 'warn',
      title: 'Sensitive services exposed to the internet',
      detail: risky.join(', ') + '. These are rarely intended to be publicly reachable.',
    });
  }

  if (data.reputation?.malicious > 0) {
    findings.push({
      level: 'danger',
      title: `Flagged by ${data.reputation.malicious} security vendor(s)`,
      detail: `${data.reputation.harmless} vendors rate it harmless.`,
    });
  }

  if (data.neighbours?.shared) {
    findings.push({
      level: 'info',
      title: `${data.neighbours.count} domains share this address`,
      detail: 'Shared hosting or a CDN front. The address does not identify a single owner, and any one domain on it is weak evidence about the others.',
    });
  } else if (data.neighbours?.count === 1) {
    findings.push({
      level: 'info',
      title: 'Single domain on this address',
      detail: `Only ${data.neighbours.domains[0]} resolves here, which suggests dedicated hosting.`,
    });
  }

  if (data.routing?.originAsns?.length) {
    const origin = data.routing.originAsns[0];
    findings.push({
      level: 'info',
      title: `Announced by ${origin.asn}${origin.holder ? ` — ${origin.holder}` : ''}`,
      detail: `Routed as part of ${data.routing.announcedPrefix}. Who announces a prefix is harder to falsify than a geolocation record.`,
    });
  }

  if (!data.ptr) {
    findings.push({ level: 'info', title: 'No reverse DNS', detail: 'No PTR record is published for this address.' });
  }

  if (!findings.length) {
    findings.push({ level: 'ok', title: 'Nothing notable', detail: 'No exposed CVEs, abuse reports or risky open ports were found in the sources checked.' });
  }
  return findings;
}

/** Deep links into third-party tools, for the manual half of an investigation. */
function pivots(ip) {
  return [
    { label: 'Shodan', url: `https://www.shodan.io/host/${ip}` },
    { label: 'Censys', url: `https://search.censys.io/hosts/${ip}` },
    { label: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${ip}` },
    { label: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${ip}` },
    { label: 'GreyNoise', url: `https://viz.greynoise.io/ip/${ip}` },
    { label: 'BGP.tools', url: `https://bgp.tools/ip/${ip}` },
  ];
}
