/**
 * IP address reconnaissance.
 *
 * GhostTrack's original IP tracker was a single call to ipwho.is printed to a
 * terminal. This keeps that geolocation but adds the parts that actually matter
 * for an investigation: who owns the netblock (RDAP), who announces it (BGP),
 * what the operator says about the address themselves (RFC 8805 geofeed), what
 * it calls itself (PTR), what it exposes (Shodan InternetDB), what mail
 * operators think of it (DNSBLs), and whether it looks like infrastructure
 * rather than a person.
 */

import { getJson, getText, gather } from '../lib/http.js';
import { reverseLookup, resolveBatch } from '../lib/dns.js';
import { parseIp } from '../lib/validate.js';
import { DNSBLS, isResolverRefusal, readPtr, hostingOperator } from '../lib/providers.js';
import * as rdap from '../lib/rdap.js';

export async function lookupIp(input, env = {}, options = {}) {
  const ip = parseIp(input);
  const deep = options.depth === 'deep';

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
    threat: () => dshield(ip.value),
    allocation: () => bgpView(ip.value),
    abuseContact: () => ripeAbuseContact(ip.value),
    anonymity: () => torRelay(ip.value),
    ...(ip.version === 4 ? { blocklists: () => checkDnsbls(ip.value) } : {}),
    ...(deep ? { history: () => routingHistory(ip.value) } : {}),
    ...(env.ABUSEIPDB_API_KEY ? { abuse: () => abuseIpDb(ip.value, env.ABUSEIPDB_API_KEY) } : {}),
    ...(env.VIRUSTOTAL_API_KEY ? { reputation: () => virusTotalIp(ip.value, env.VIRUSTOTAL_API_KEY) } : {}),
    ...(env.GREYNOISE_API_KEY ? { noise: () => greyNoise(ip.value, env.GREYNOISE_API_KEY) } : {}),
    ...(env.SHODAN_API_KEY ? { host: () => shodanHost(ip.value, env.SHODAN_API_KEY) } : {}),
  });

  // Second wave. Both of these are keyed by something the first wave had to
  // discover, so they cost one extra round trip rather than a whole extra pass.
  const asn = data.routing?.originAsns?.[0]?.asn ?? data.allocation?.asn ?? data.geo?.asn ?? null;
  const geofeedUrl = data.registry?.geofeedUrl ?? null;

  const [network, autnum, geofeed] = await Promise.all([
    asn ? peeringDb(asn).catch(() => null) : null,
    asn && deep ? asnRegistry(asn).catch(() => null) : null,
    geofeedUrl ? readGeofeed(geofeedUrl, ip.value).catch((err) => ({ error: err.message })) : null,
  ]);

  if (asn) sources.peeringDb = { ok: network !== null };
  if (asn && deep) sources.asnRegistry = { ok: autnum !== null };

  // Three outcomes, and collapsing them loses the interesting one. "No geofeed
  // is published", "a geofeed exists but does not list this prefix" and "the
  // geofeed could not be read" are different facts, and only the last is a
  // source failure. The middle one says the operator maintains self-published
  // geolocation and chose not to describe this block.
  if (geofeedUrl) {
    sources.geofeed = geofeed?.error ? { ok: false, error: geofeed.error } : { ok: true };
  }
  const geofeedMatch = geofeed?.covered ? geofeed : null;

  const ptrIntel = readPtr(data.ptr);

  return {
    query: { type: 'ip', value: ip.value, version: ip.version, depth: options.depth ?? 'standard' },
    routable: true,
    scope: ip.scope,
    geolocation: data.geo?.best ?? null,
    geolocationProviders: data.geo?.providers ?? [],
    geolocationAgreement: data.geo?.agreement ?? null,
    // The operator's own published geolocation, when they publish one. This
    // outranks every commercial database in the panel above it.
    geofeed: geofeedMatch,
    geofeedStatus: geofeedUrl
      ? {
        url: geofeedUrl,
        covered: Boolean(geofeedMatch),
        note: geofeedMatch
          ? 'The operator publishes a geofeed and it covers this address.'
          : geofeed?.error
            ? `A geofeed is advertised at ${geofeedUrl} but could not be read: ${geofeed.error}`
            : `The operator publishes a geofeed at ${geofeedUrl}, but it does not list a prefix covering this address.`,
      }
      : null,
    registry: data.registry,
    allocation: data.allocation,
    asnRegistry: autnum,
    reverseDns: data.ptr,
    reverseDnsIntel: ptrIntel,
    routing: data.routing,
    routingHistory: data.history ?? null,
    threat: data.threat,
    blocklists: data.blocklists ?? null,
    anonymity: data.anonymity ?? null,
    abuseContacts: data.abuseContact ?? null,
    network,
    hostedDomains: data.neighbours,
    exposure: data.exposure,
    shodan: data.host ?? null,
    abuse: data.abuse ?? null,
    reputation: data.reputation ?? null,
    noise: data.noise ?? null,
    classification: classify(data, ptrIntel),
    assessment: assess(data, ptrIntel, geofeedMatch, geofeedUrl),
    pivots: pivots(ip.value, asn),
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
 * Geolocation, across every provider that answers.
 *
 * The previous version took the first success and stopped. That hides the most
 * useful thing about free geo-IP: the providers disagree, often by hundreds of
 * kilometres, and how much they disagree is the only honest measure of how much
 * the answer is worth. So all of them run, the most detailed answer leads, and
 * the spread between them is reported alongside it.
 *
 * Free geo-IP APIs also meter by source address, and on Workers the source
 * address is Cloudflare's shared egress — a per-IP monthly quota is routinely
 * spent by unrelated traffic before our request arrives. Running several in
 * parallel means a quota exhaustion on one no longer blanks the panel.
 */
async function geolocate(ip) {
  const providers = [ipwhois, ipApi, ipApiCo, ripeStatGeo];
  const settled = await Promise.allSettled(providers.map((p) => p(ip)));
  const answers = settled.filter((s) => s.status === 'fulfilled').map((s) => s.value);

  if (!answers.length) {
    throw settled[0]?.reason ?? new Error('No geolocation provider responded');
  }

  // Rank by how specific the answer is; a city beats a country centroid.
  const rank = { city: 0, region: 1, country: 2 };
  const sorted = answers.slice().sort((a, b) => (rank[a.precision] ?? 3) - (rank[b.precision] ?? 3));
  const best = sorted[0];

  return { best, providers: answers, agreement: agreement(answers) };
}

/**
 * How far apart the providers actually are.
 *
 * Reported as the widest gap between any two answers, because that is the
 * number that tells you whether "London" and "Slough" are the same finding.
 */
function agreement(answers) {
  // Only real coordinates and real country codes count. Providers signal "no
  // answer" in-band with placeholders, and a placeholder counted as a distinct
  // answer manufactures a disagreement that does not exist.
  const located = answers.filter((a) =>
    Number.isFinite(a.latitude) && Number.isFinite(a.longitude)
    && !(a.latitude === 0 && a.longitude === 0));
  const countries = [...new Set(
    answers.map((a) => a.countryCode).filter((c) => /^[A-Z]{2}$/i.test(c ?? '')),
  )];
  const cities = [...new Set(answers.map((a) => a.city).filter(Boolean))];

  let spreadKm = null;
  for (let i = 0; i < located.length; i++) {
    for (let j = i + 1; j < located.length; j++) {
      const distance = haversineKm(located[i], located[j]);
      if (spreadKm == null || distance > spreadKm) spreadKm = Math.round(distance);
    }
  }

  return {
    providers: answers.length,
    countries,
    cities,
    countryConsensus: countries.length <= 1,
    cityConsensus: cities.length <= 1,
    spreadKm,
    verdict: countries.length > 1
      ? 'Providers disagree on the country — treat the location as unknown.'
      : spreadKm != null && spreadKm > 100
        ? `Providers place this address up to ${spreadKm} km apart. The city is not reliable.`
        : cities.length > 1
          ? 'Providers agree on the country but name different cities.'
          : 'Providers agree.',
  };
}

function haversineKm(a, b) {
  const toRad = (deg) => (deg * Math.PI) / 180;
  const dLat = toRad(b.latitude - a.latitude);
  const dLon = toRad(b.longitude - a.longitude);
  const lat1 = toRad(a.latitude);
  const lat2 = toRad(b.latitude);
  const h = Math.sin(dLat / 2) ** 2 + Math.sin(dLon / 2) ** 2 * Math.cos(lat1) * Math.cos(lat2);
  return 6371 * 2 * Math.asin(Math.sqrt(h));
}

/** RIPE NCC's own geolocation. Country-level only, but effectively unmetered. */
async function ripeStatGeo(ip) {
  const body = await getJson(
    `https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${encodeURIComponent(ip)}`,
    { source: 'stat.ripe.net', timeout: 9000 },
  );

  const location = body.data?.located_resources?.[0]?.locations?.[0];

  // RIPEstat answers "I don't know" in-band: the country comes back as "?" and
  // the coordinates as 0,0. Both are placeholders, and both do real damage if
  // treated as data — "?" becomes a third country in the consensus check, and
  // 0,0 is a point in the Gulf of Guinea that inflates the spread between
  // providers to most of the planet.
  const country = location?.country && location.country !== '?' ? location.country : null;
  if (!country) throw new Error('RIPEstat has no geolocation for this address');

  const latitude = Number(location.latitude);
  const longitude = Number(location.longitude);
  const located = Number.isFinite(latitude) && Number.isFinite(longitude)
    && !(latitude === 0 && longitude === 0);

  return {
    provider: 'stat.ripe.net',
    country,
    countryCode: country,
    flag: null,
    region: null,
    city: location.city || null,
    postal: null,
    continent: null,
    latitude: located ? latitude : null,
    longitude: located ? longitude : null,
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
      '?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting',
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
    // ip-api is the only free provider that classifies the connection, and the
    // classification is worth more than the coordinates.
    isMobile: body.mobile ?? null,
    isProxy: body.proxy ?? null,
    isHosting: body.hosting ?? null,
    mapUrl: body.lat != null
      ? `https://www.openstreetmap.org/?mlat=${body.lat}&mlon=${body.lon}#map=11/${body.lat}/${body.lon}`
      : null,
  };
}

/** ipapi.co. Another city-level view, with its own independent dataset. */
async function ipApiCo(ip) {
  const body = await getJson(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
    source: 'ipapi.co',
    timeout: 8000,
  });
  if (body.error) throw new Error(`ipapi.co could not resolve ${ip}: ${body.reason ?? 'no detail given'}`);

  return {
    provider: 'ipapi.co',
    country: body.country_name ?? null,
    countryCode: body.country_code ?? null,
    flag: null,
    region: body.region ?? null,
    city: body.city ?? null,
    postal: body.postal ?? null,
    continent: body.continent_code ?? null,
    latitude: body.latitude ?? null,
    longitude: body.longitude ?? null,
    precision: body.city ? 'city' : body.region ? 'region' : 'country',
    timezone: body.timezone ? { id: body.timezone, utcOffset: body.utc_offset ?? null, abbreviation: null } : null,
    isp: body.org ?? null,
    organization: body.org ?? null,
    asn: body.asn ?? null,
    asnDomain: null,
    callingCode: body.country_calling_code ?? null,
    isEu: body.in_eu ?? null,
    mapUrl: body.latitude != null
      ? `https://www.openstreetmap.org/?mlat=${body.latitude}&mlon=${body.longitude}#map=11/${body.latitude}/${body.longitude}`
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
    technical: roles.technical ?? null,
    // The parent allocation, when the registry exposes one.
    parent: body.parentHandle ?? null,
    // Free-text remarks frequently carry the operator's own notes: an abuse
    // policy, a routing statement, a "this range is used for X" line.
    remarks: rdap.remarkText(body.remarks).slice(0, 6),
    geofeedUrl: rdap.geofeedUrl(body),
  };
}

/**
 * RFC 8805 geofeed.
 *
 * A geofeed is a CSV the *network operator themselves* publishes, mapping their
 * own prefixes to the country, region and city they are actually deployed in.
 * Where one exists it is categorically better evidence than any commercial
 * geo-IP database, because the operator is the only party who actually knows —
 * everyone else is inferring. Almost nothing surfaces these, and they are
 * exactly what makes a datacenter range resolvable to a real city.
 */
async function readGeofeed(url, ip) {
  const text = await getText(url, { source: new URL(url).hostname, timeout: 8000 });
  if (/<html|<!doctype/i.test(text)) throw new Error('Geofeed URL served HTML, not a CSV');

  const target = ipToBigInt(ip);
  const isV6 = ip.includes(':');
  let match = null;

  for (const line of text.split('\n')) {
    const row = line.trim();
    if (!row || row.startsWith('#')) continue;

    // prefix,country,region,city,postal
    const [prefix, country, region, city, postal] = row.split(',').map((f) => f?.trim() ?? '');
    if (!prefix.includes('/')) continue;
    if (prefix.includes(':') !== isV6) continue;

    const [network, lengthText] = prefix.split('/');
    const length = Number(lengthText);
    if (!Number.isFinite(length)) continue;

    let base;
    try {
      base = ipToBigInt(network);
    } catch {
      continue;
    }

    const bits = BigInt(isV6 ? 128 : 32) - BigInt(length);
    if ((target >> bits) !== (base >> bits)) continue;

    // Longest prefix wins, exactly as it would in a routing table.
    if (!match || length > match.length) {
      match = { prefix, length, country: country || null, region: region || null, city: city || null, postal: postal || null };
    }
  }

  // Not covered is an answer, not a failure: the geofeed was fetched and parsed
  // successfully, and it simply does not describe this block. Throwing here
  // would report a working source as broken.
  if (!match) return { covered: false, source: url };

  return { ...match, covered: true, source: url, note: 'Self-published by the network operator under RFC 8805.' };
}

/** Numeric value of an address, for prefix arithmetic. */
function ipToBigInt(ip) {
  if (!ip.includes(':')) {
    return ip.split('.').reduce((acc, octet) => (acc << 8n) + BigInt(Number(octet)), 0n);
  }
  const [head, tail = ''] = ip.split('::');
  const headGroups = head ? head.split(':').filter(Boolean) : [];
  const tailGroups = tail ? tail.split(':').filter(Boolean) : [];
  const groups = ip.includes('::')
    ? [...headGroups, ...Array(8 - headGroups.length - tailGroups.length).fill('0'), ...tailGroups]
    : ip.split(':');
  return groups.reduce((acc, group) => (acc << 16n) + BigInt(parseInt(group, 16) || 0), 0n);
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

/** Full Shodan host record — service banners and versions. Needs a key. */
async function shodanHost(ip, key) {
  const body = await getJson(
    `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`,
    { source: 'api.shodan.io', timeout: 10000 },
  );

  return {
    organization: body.org ?? null,
    operatingSystem: body.os ?? null,
    lastUpdate: body.last_update ?? null,
    // The banner detail is the payoff of a key: product name and version per
    // port, which is what turns "443 is open" into an identifiable stack.
    services: (body.data ?? []).slice(0, 25).map((service) => ({
      port: service.port,
      transport: service.transport ?? null,
      product: service.product ?? null,
      version: service.version ?? null,
      module: service._shodan?.module ?? null,
      title: service.http?.title ?? null,
      server: service.http?.server ?? null,
      certificateSubject: service.ssl?.cert?.subject?.CN ?? null,
      certificateIssuer: service.ssl?.cert?.issuer?.O ?? null,
      timestamp: service.timestamp ?? null,
    })),
  };
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
 * How this prefix has been announced over time.
 *
 * A prefix that has changed origin AS is the single clearest routing-level
 * signal there is: it means the block was transferred, leased, or hijacked.
 * Nothing in a point-in-time lookup can show that, and it is the kind of detail
 * an investigator would otherwise have to pull from a BGP archive by hand.
 */
async function routingHistory(ip) {
  const body = await getJson(
    `https://stat.ripe.net/data/routing-history/data.json?resource=${encodeURIComponent(ip)}&max_rows=40`,
    { source: 'stat.ripe.net', timeout: 12000 },
  );

  const origins = (body.data?.by_origin ?? []).map((entry) => {
    const spans = entry.prefixes?.flatMap((p) => p.timelines ?? []) ?? [];
    const starts = spans.map((t) => t.starttime).filter(Boolean).sort();
    const ends = spans.map((t) => t.endtime).filter(Boolean).sort();
    return {
      asn: `AS${entry.origin}`,
      prefixes: (entry.prefixes ?? []).map((p) => p.prefix).slice(0, 5),
      firstSeen: starts[0]?.slice(0, 10) ?? null,
      lastSeen: ends[ends.length - 1]?.slice(0, 10) ?? null,
    };
  });

  return {
    origins: origins.slice(0, 10),
    originCount: origins.length,
    // More than one origin over the window is the finding worth surfacing.
    changedHands: origins.length > 1,
    window: body.data?.query_starttime
      ? `${body.data.query_starttime.slice(0, 10)} → ${(body.data.query_endtime ?? '').slice(0, 10)}`
      : null,
  };
}

/**
 * RIPEstat's abuse-contact-finder.
 *
 * It walks the RIR hierarchy up from the address until it finds a contact that
 * is actually maintained, which routinely surfaces an address the RDAP record
 * for the specific netblock does not carry.
 */
async function ripeAbuseContact(ip) {
  const body = await getJson(
    `https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${encodeURIComponent(ip)}`,
    { source: 'stat.ripe.net', timeout: 8000 },
  );

  const d = body.data ?? {};
  const emails = d.abuse_contacts ?? [];
  if (!emails.length && !d.authoritative_rir) throw new Error('No abuse contact published for this address');

  return {
    emails,
    authoritativeRir: d.authoritative_rir ?? null,
    // "false" here means the RIR did not mark the contact as verified, which is
    // worth knowing before relying on it.
    earliestTime: d.earliest_time ?? null,
  };
}

/**
 * Address-level allocation record from BGPView.
 *
 * Overlaps RDAP deliberately: BGPView normalises across all five RIRs into one
 * shape, carries the allocation date and the RIR name explicitly, and returns
 * the covering prefix even when the RDAP server for that region is down.
 */
async function bgpView(ip) {
  const body = await getJson(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`, {
    source: 'api.bgpview.io',
    timeout: 9000,
  });
  if (body.status !== 'ok') throw new Error(`BGPView could not resolve ${ip}`);

  const d = body.data ?? {};
  const prefix = d.prefixes?.[0] ?? null;

  return {
    ptr: d.ptr_record ?? null,
    rir: d.rir_allocation?.rir_name ?? null,
    allocatedPrefix: d.rir_allocation?.prefix ?? null,
    allocationDate: d.rir_allocation?.date_allocated?.slice(0, 10) ?? null,
    allocationStatus: d.rir_allocation?.allocation_status ?? null,
    country: d.rir_allocation?.country_code ?? null,
    asn: prefix?.asn?.asn ? `AS${prefix.asn.asn}` : null,
    asnName: prefix?.asn?.name ?? null,
    asnDescription: prefix?.asn?.description ?? null,
    prefix: prefix?.prefix ?? null,
    prefixName: prefix?.name ?? null,
    prefixDescription: prefix?.description ?? null,
    // Nearby prefixes under the same allocation: the operator's wider footprint.
    coveringPrefixes: (d.prefixes ?? []).slice(0, 6).map((p) => ({
      prefix: p.prefix,
      name: p.name ?? null,
      country: p.country_code ?? null,
    })),
  };
}

/** Registry record for the announcing AS: who the network legally belongs to. */
async function asnRegistry(asn) {
  const number = String(asn).replace(/^AS/i, '');
  const body = await rdap.lookup('autnum', number);
  const roles = rdap.entitiesByRole(body.entities);

  return {
    handle: body.handle ?? null,
    name: body.name ?? null,
    type: body.type ?? null,
    country: body.country ?? null,
    registered: rdap.eventDate(body.events, 'registration'),
    updated: rdap.eventDate(body.events, 'last changed'),
    registrant: roles.registrant ?? roles.administrative ?? null,
    abuseContact: roles.abuse ?? null,
    technical: roles.technical ?? null,
  };
}

/**
 * DNS blocklist membership.
 *
 * This is what a receiving mail server sees when the address tries to talk to
 * it, and it is a far more direct read on reputation than a vendor score: a
 * Spamhaus PBL listing says "this is an end-user address", an XBL listing says
 * "this machine is compromised". Each zone is a single A lookup over the DoH
 * path everything else already uses.
 */
async function checkDnsbls(ip) {
  const reversed = ip.split('.').reverse().join('.');
  const names = DNSBLS.map((bl) => `${reversed}.${bl.zone}`);
  const results = await resolveBatch(names, 'A');

  const listings = [];
  const unavailable = [];

  results.forEach((result, i) => {
    const bl = DNSBLS[i];
    if (!result.ok) {
      unavailable.push({ name: bl.name, reason: 'lookup failed' });
      return;
    }
    if (!result.records.length) return;

    // A refusal code means the zone declined to answer a query from a large
    // public resolver — not that the address is listed. Reporting these as
    // listings would flag every address on the internet.
    if (result.records.some(isResolverRefusal)) {
      unavailable.push({ name: bl.name, reason: 'zone refuses queries from public resolvers' });
      return;
    }

    listings.push({
      name: bl.name,
      zone: bl.zone,
      codes: result.records,
      reasons: result.records.map((code) => bl.codes?.[code] ?? `listed (${code})`),
    });
  });

  return {
    checked: DNSBLS.length,
    usable: DNSBLS.length - unavailable.length,
    listedOn: listings.length,
    listings,
    unavailable,
  };
}

/**
 * Tor relay membership, from the Tor Project's own directory.
 *
 * Onionoo is the authoritative source and needs no key. This matters more than
 * any generic "proxy?" flag: if the address is an exit relay, the traffic
 * behind it belongs to somebody else entirely and no amount of geolocation will
 * ever point at a person.
 */
async function torRelay(ip) {
  const body = await getJson(
    `https://onionoo.torproject.org/details?search=${encodeURIComponent(ip)}&limit=4`,
    { source: 'onionoo.torproject.org', timeout: 9000 },
  );

  const relays = body.relays ?? [];
  const match = relays.find((r) =>
    (r.or_addresses ?? []).some((address) => address.split(':').slice(0, -1).join(':').replace(/[[\]]/g, '') === ip) ||
    (r.exit_addresses ?? []).includes(ip));

  if (!match) return { tor: false, relay: null };

  return {
    tor: true,
    relay: {
      nickname: match.nickname ?? null,
      fingerprint: match.fingerprint ?? null,
      flags: match.flags ?? [],
      isExit: (match.flags ?? []).includes('Exit'),
      isGuard: (match.flags ?? []).includes('Guard'),
      running: match.running ?? null,
      firstSeen: match.first_seen?.slice(0, 10) ?? null,
      lastSeen: match.last_seen?.slice(0, 10) ?? null,
      contact: match.contact ?? null,
      platform: match.platform ?? null,
      bandwidthMbps: match.observed_bandwidth
        ? Math.round((match.observed_bandwidth * 8) / 1_000_000)
        : null,
      country: match.country_name ?? null,
      exitPolicySummary: match.exit_policy_summary ?? null,
    },
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

/**
 * SANS Internet Storm Center.
 *
 * DShield aggregates firewall logs from thousands of sensors, so it answers
 * "has this address been attacking people" without an API key — the signal
 * AbuseIPDB provides only once you register. A null count means the sensors
 * have simply never logged it, which is a clean result rather than an error.
 */
async function dshield(ip) {
  const body = await getJson(`https://isc.sans.edu/api/ip/${encodeURIComponent(ip)}?json`, {
    source: 'isc.sans.edu',
    timeout: 8000,
  });

  const d = body.ip ?? {};
  const attacks = d.attacks == null ? null : Number(d.attacks);

  return {
    seen: attacks != null,
    // Distinct target networks that logged this address.
    targets: attacks,
    // Total records submitted for it.
    records: d.count == null ? null : Number(d.count),
    firstSeen: d.mindate ?? null,
    lastSeen: d.maxdate ?? null,
    network: d.asname ?? null,
    cloudProvider: d.cloud ?? null,
    threatFeeds: (d.threatfeeds && typeof d.threatfeeds === 'object')
      ? Object.keys(d.threatfeeds).slice(0, 12)
      : [],
  };
}

/**
 * PeeringDB, the operator-maintained registry of networks.
 *
 * Where RDAP gives the legal holder of a netblock, PeeringDB gives the network
 * as its operators describe it: traffic volume, scope, peering policy, and a
 * published NOC contact — often the most direct route to a human.
 */
async function peeringDb(asn) {
  const number = String(asn).replace(/^AS/i, '');
  if (!/^\d+$/.test(number)) throw new Error('No usable ASN for a PeeringDB lookup');

  const body = await getJson(`https://www.peeringdb.com/api/net?asn=${number}`, {
    source: 'peeringdb.com',
    timeout: 9000,
  });

  const net = body.data?.[0];
  if (!net) throw new Error(`PeeringDB has no record for AS${number}`);

  return {
    asn: `AS${number}`,
    name: net.name ?? null,
    alsoKnownAs: net.aka || null,
    website: net.website || null,
    // How the operator describes its own reach and volume. Optional fields —
    // plenty of networks leave them blank.
    trafficLevels: net.info_traffic || null,
    scope: net.info_scope || null,
    networkType: net.info_type || null,
    ratios: net.info_ratio || null,
    peeringPolicy: net.policy_general || null,
    policyUrl: net.policy_url || null,
    // Declared prefix counts and peering reach: a rough size indicator.
    prefixesV4: net.info_prefixes4 ?? null,
    prefixesV6: net.info_prefixes6 ?? null,
    exchangeCount: net.ix_count ?? null,
    facilityCount: net.fac_count ?? null,
    // The IRR AS-SET is the authoritative list of what this network announces.
    irrAsSet: net.irr_as_set || null,
    lookingGlass: net.looking_glass || null,
    nocContact: net.poc_email || null,
    peeringDbUrl: `https://www.peeringdb.com/net/${net.id}`,
  };
}

async function abuseIpDb(ip, key) {
  const body = await getJson(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=`,
    { source: 'abuseipdb.com', headers: { Key: key, Accept: 'application/json' } },
  );
  const d = body.data ?? {};
  return {
    confidenceScore: d.abuseConfidenceScore ?? null,
    totalReports: d.totalReports ?? 0,
    distinctReporters: d.numDistinctUsers ?? 0,
    lastReportedAt: d.lastReportedAt ?? null,
    usageType: d.usageType ?? null,
    domain: d.domain ?? null,
    hostnames: d.hostnames ?? [],
    isTor: d.isTor ?? null,
    isWhitelisted: d.isWhitelisted ?? null,
    // Report categories say *what* the address was reported for, which is more
    // actionable than the score on its own.
    recentReports: (d.reports ?? []).slice(0, 5).map((r) => ({
      reportedAt: r.reportedAt?.slice(0, 10) ?? null,
      categories: r.categories ?? [],
      comment: (r.comment ?? '').slice(0, 200) || null,
      reporterCountry: r.reporterCountryCode ?? null,
    })),
  };
}

async function virusTotalIp(ip, key) {
  const body = await getJson(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
    source: 'virustotal.com',
    headers: { 'x-apikey': key },
  });
  const attributes = body.data?.attributes ?? {};
  const stats = attributes.last_analysis_stats ?? {};
  return {
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    undetected: stats.undetected ?? 0,
    reputation: attributes.reputation ?? null,
    // Community votes and the last-seen certificate are extra context a raw
    // score cannot convey.
    votesMalicious: attributes.total_votes?.malicious ?? null,
    votesHarmless: attributes.total_votes?.harmless ?? null,
    certificateSubject: attributes.last_https_certificate?.subject?.CN ?? null,
    flaggedBy: Object.entries(attributes.last_analysis_results ?? {})
      .filter(([, result]) => result.category === 'malicious')
      .map(([vendor]) => vendor)
      .slice(0, 12),
  };
}

/**
 * GreyNoise: is this address scanning the whole internet, or targeting you?
 *
 * The distinction is the entire product — "benign background noise" versus
 * "this was aimed at you" changes the response to an alert completely.
 */
async function greyNoise(ip, key) {
  const body = await getJson(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, {
    source: 'api.greynoise.io',
    headers: { key },
    timeout: 8000,
  });

  return {
    noise: body.noise ?? null,
    riot: body.riot ?? null,
    classification: body.classification ?? null,
    name: body.name ?? null,
    lastSeen: body.last_seen ?? null,
    link: body.link ?? null,
  };
}

/* ------------------------------------------------------------- classification */

/**
 * What kind of address is this?
 *
 * Every other signal in the report reads differently depending on the answer.
 * A city on a datacenter address is a rack; a city on a residential address is
 * roughly a person. Rather than leaving that inference to the reader, it is
 * made once, explicitly, from the evidence that supports it.
 */
function classify(data, ptrIntel) {
  const evidence = [];
  const org = [data.geo?.best?.organization, data.geo?.best?.isp, data.registry?.name,
    data.allocation?.asnName, data.allocation?.asnDescription].filter(Boolean).join(' ');

  const operator = hostingOperator(org, data.ptr ?? '');
  if (operator) evidence.push({ signal: 'operator', detail: `Network belongs to ${operator}` });

  const ipApiAnswer = (data.geo?.providers ?? []).find((p) => p.provider === 'ip-api.com');
  if (ipApiAnswer?.isHosting) evidence.push({ signal: 'hosting flag', detail: 'ip-api.com classifies this as hosting/datacenter' });
  if (ipApiAnswer?.isMobile) evidence.push({ signal: 'mobile flag', detail: 'ip-api.com classifies this as a mobile carrier address' });
  if (ipApiAnswer?.isProxy) evidence.push({ signal: 'proxy flag', detail: 'ip-api.com classifies this as a proxy or VPN' });

  if (ptrIntel?.platform) evidence.push({ signal: 'reverse DNS', detail: `PTR names ${ptrIntel.platform}` });
  if (ptrIntel?.kind) evidence.push({ signal: 'reverse DNS', detail: `PTR pattern suggests ${ptrIntel.kind}` });

  if (data.anonymity?.tor) {
    evidence.push({ signal: 'Tor directory', detail: `Listed as a Tor relay${data.anonymity.relay?.isExit ? ' with the Exit flag' : ''}` });
  }
  if (data.abuse?.usageType) evidence.push({ signal: 'AbuseIPDB', detail: `Usage type: ${data.abuse.usageType}` });

  const pbl = data.blocklists?.listings?.find((l) => l.reasons.some((r) => /end-user|dynamic/i.test(r)));
  if (pbl) evidence.push({ signal: 'blocklist', detail: `${pbl.name} lists this as an end-user or dynamic address` });

  // Decide from the strongest evidence available, in order of reliability.
  let kind = 'unknown';
  if (data.anonymity?.tor) kind = 'tor';
  else if (ipApiAnswer?.isProxy) kind = 'proxy/vpn';
  else if (ipApiAnswer?.isMobile || /cellular|mobile/i.test(data.abuse?.usageType ?? '')) kind = 'mobile';
  else if (operator || ipApiAnswer?.isHosting || ptrIntel?.platform || /data center|hosting/i.test(data.abuse?.usageType ?? '')) kind = 'datacenter';
  else if (pbl || /residential|isp/i.test(data.abuse?.usageType ?? '') || /residential|access/i.test(ptrIntel?.kind ?? '')) kind = 'residential';

  const meaning = {
    datacenter: 'Infrastructure. Geolocation describes a rack, not a person, and the interesting question is who rents it.',
    residential: 'A consumer access line. The geolocation is roughly meaningful, but the address is likely dynamic and shared over time.',
    mobile: 'A mobile carrier address. It is shared by many subscribers through CGNAT and moves constantly; geolocation is near-worthless.',
    'proxy/vpn': 'An anonymising service. Traffic from it belongs to a customer, not to the address holder.',
    tor: 'A Tor relay. Traffic leaving it originated somewhere else entirely and cannot be attributed to this address.',
    unknown: 'Not enough signal to classify. Weigh the geolocation cautiously.',
  }[kind];

  return { kind, operator, region: ptrIntel?.region ?? null, meaning, evidence };
}

/* --------------------------------------------------------------- assessment */

/**
 * Turn the raw signals into a short list of plain-language findings, so the
 * report leads with meaning instead of with JSON.
 */
function assess(data, ptrIntel, geofeed, geofeedUrl) {
  const findings = [];

  if (geofeed) {
    findings.push({
      level: 'ok',
      title: `Operator publishes a geofeed: ${[geofeed.city, geofeed.region, geofeed.country].filter(Boolean).join(', ')}`,
      detail: `Under RFC 8805 the network operator declares ${geofeed.prefix} as being deployed here. This is the operator's own statement and outranks every commercial geolocation database.`,
    });
  }

  if (!geofeed && geofeedUrl) {
    findings.push({
      level: 'info',
      title: 'Operator publishes a geofeed, but not for this prefix',
      detail: `A geofeed exists at ${geofeedUrl} and does not list a prefix covering this address. The operator maintains self-published geolocation for some of their space and has chosen not to describe this block, so the databases below are all you have here.`,
    });
  }

  if (data.geo?.agreement && !data.geo.agreement.countryConsensus) {
    findings.push({
      level: 'warn',
      title: 'Geolocation providers disagree on the country',
      detail: `${data.geo.agreement.countries.join(', ')} were all returned for this address. Do not rely on any of them.`,
    });
  } else if (data.geo?.agreement?.spreadKm > 100) {
    findings.push({
      level: 'warn',
      title: `Geolocation varies by up to ${data.geo.agreement.spreadKm} km between providers`,
      detail: `Cities returned: ${data.geo.agreement.cities.join(', ') || 'none'}. The country is agreed, the city is not.`,
    });
  }

  if (data.anonymity?.tor) {
    const relay = data.anonymity.relay;
    findings.push({
      level: 'warn',
      title: relay.isExit ? 'Tor exit relay' : 'Tor relay',
      detail: `Listed in the Tor directory as "${relay.nickname}"${relay.firstSeen ? `, first seen ${relay.firstSeen}` : ''}. `
        + (relay.isExit
          ? 'Traffic leaving this address originated with an anonymous user elsewhere and cannot be attributed to the address holder.'
          : 'It relays traffic between other relays and does not originate user traffic.')
        + (relay.contact ? ` Operator contact: ${relay.contact}` : ''),
    });
  }

  const listed = data.blocklists?.listings ?? [];
  if (listed.length) {
    findings.push({
      level: listed.length > 2 ? 'danger' : 'warn',
      title: `Listed on ${listed.length} of ${data.blocklists.usable} usable DNS blocklists`,
      detail: listed.map((l) => `${l.name}: ${l.reasons.join('; ')}`).join(' · ')
        + '. This is what a receiving mail server sees when this address tries to deliver.',
    });
  } else if (data.blocklists?.usable > 0) {
    findings.push({
      level: 'ok',
      title: `Clean on ${data.blocklists.usable} DNS blocklists`,
      detail: 'No spam, proxy or compromised-host listing found on the zones that answered.',
    });
  }

  if (data.threat?.seen && data.threat.targets > 0) {
    const heavy = data.threat.targets > 100;
    findings.push({
      level: heavy ? 'danger' : 'warn',
      title: `Logged attacking ${data.threat.targets.toLocaleString()} network(s)`,
      detail: `SANS Internet Storm Center sensors recorded ${(data.threat.records ?? 0).toLocaleString()} events`
        + (data.threat.lastSeen ? `, most recently ${data.threat.lastSeen}` : '')
        + '. This is firewall-log evidence of scanning or attack traffic.',
    });
  }
  if (data.threat?.threatFeeds?.length) {
    findings.push({
      level: 'danger',
      title: `Listed on ${data.threat.threatFeeds.length} threat feed(s)`,
      detail: data.threat.threatFeeds.join(', '),
    });
  }

  if (data.noise?.classification === 'malicious') {
    findings.push({
      level: 'danger',
      title: 'GreyNoise classifies this as malicious',
      detail: `${data.noise.name ?? 'Unnamed actor'}. GreyNoise sees internet-wide scanning, so this address is opportunistic rather than targeted at you specifically.`,
    });
  } else if (data.noise?.riot) {
    findings.push({
      level: 'ok',
      title: 'Known benign service (GreyNoise RIOT)',
      detail: `${data.noise.name ?? 'A common business service'}. Traffic from it is expected and generally safe to ignore.`,
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
      detail: (data.reputation.flaggedBy?.length ? `${data.reputation.flaggedBy.join(', ')}. ` : '')
        + `${data.reputation.harmless} vendors rate it harmless.`,
    });
  }

  if (data.history?.changedHands) {
    findings.push({
      level: 'warn',
      title: `Prefix has been announced by ${data.history.originCount} different networks`,
      detail: data.history.origins.map((o) => `${o.asn} (${o.firstSeen ?? '?'} → ${o.lastSeen ?? 'now'})`).join(', ')
        + '. A change of origin AS means the block was transferred, leased, or hijacked — worth confirming which.',
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

  if (data.allocation?.allocationDate) {
    findings.push({
      level: 'info',
      title: `Netblock allocated ${data.allocation.allocationDate} by ${data.allocation.rir ?? 'its RIR'}`,
      detail: `${data.allocation.allocatedPrefix ?? 'The covering block'} — allocation age is a useful sanity check against a network claiming a longer history than it has.`,
    });
  }

  if (ptrIntel?.region) {
    findings.push({
      level: 'info',
      title: `Reverse DNS pins the region as ${ptrIntel.region}`,
      detail: `${ptrIntel.platform} encodes its region in the PTR record, which is more precise than the geolocation databases for cloud addresses.`,
    });
  }

  if (data.abuseContact?.emails?.length) {
    findings.push({
      level: 'info',
      title: 'Abuse contact published',
      detail: `${data.abuseContact.emails.join(', ')} (via ${data.abuseContact.authoritativeRir ?? 'the RIR hierarchy'}).`,
    });
  }

  if (!data.ptr) {
    findings.push({ level: 'info', title: 'No reverse DNS', detail: 'No PTR record is published for this address.' });
  }

  if (!findings.some((f) => f.level === 'warn' || f.level === 'danger')) {
    findings.unshift({ level: 'ok', title: 'Nothing notable', detail: 'No exposed CVEs, abuse reports, blocklist entries or risky open ports were found in the sources checked.' });
  }
  return findings;
}

/** Deep links into third-party tools, for the manual half of an investigation. */
function pivots(ip, asn) {
  const links = [
    { label: 'Shodan', url: `https://www.shodan.io/host/${ip}` },
    { label: 'Censys', url: `https://search.censys.io/hosts/${ip}` },
    { label: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${ip}` },
    { label: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${ip}` },
    { label: 'GreyNoise', url: `https://viz.greynoise.io/ip/${ip}` },
    { label: 'BGP.tools', url: `https://bgp.tools/ip/${ip}` },
    { label: 'Spur', url: `https://spur.us/context/${ip}` },
    { label: 'ONYPHE', url: `https://search.onyphe.io/search?q=ip%3A${encodeURIComponent(ip)}` },
    { label: 'ViewDNS reverse', url: `https://viewdns.info/reverseip/?host=${ip}&t=1` },
    { label: 'MXToolbox blacklists', url: `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${ip}` },
    { label: 'Wayback by IP', url: `https://urlscan.io/search/#page.ip%3A${encodeURIComponent(ip)}` },
  ];
  if (asn) {
    const number = String(asn).replace(/^AS/i, '');
    links.push({ label: `BGP.tools ${asn}`, url: `https://bgp.tools/as/${number}` });
    links.push({ label: `Prefixes of ${asn}`, url: `https://bgpview.io/asn/${number}#prefixes` });
  }
  return links;
}
