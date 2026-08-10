/**
 * Autonomous system reconnaissance.
 *
 * An IP lookup answers "who announces this address"; this answers the question
 * that follows — what *is* that network. It is the level at which infrastructure
 * actually gets attributed: an AS number is registered to a legal entity, its
 * prefixes are the full list of addresses that entity announces, and its
 * upstreams and peers describe who is willing to carry its traffic. For anything
 * bulletproof-hosting shaped, the peer list is the finding: the transit
 * providers are the parties with a contract and an abuse desk.
 */

import { getJson, gather } from '../lib/http.js';
import { parseAsn } from '../lib/validate.js';
import * as rdap from '../lib/rdap.js';

export async function lookupAsn(input, env = {}, options = {}) {
  const asn = parseAsn(input);
  const deep = options.depth === 'deep';

  if (asn.reserved) {
    return {
      query: { type: 'asn', value: asn.label, number: asn.value },
      public: false,
      summary: `${asn.label} is in a private, reserved or documentation range. Numbers like these are used inside single organisations and are never announced on the public internet, so no registry or routing data exists for it.`,
      sources: {},
    };
  }

  const { data, sources } = await gather({
    registry: () => registryRecord(asn.value),
    profile: () => bgpViewAsn(asn.value),
    overview: () => ripeOverview(asn.value),
    network: () => peeringDb(asn.value),
    prefixes: () => bgpViewPrefixes(asn.value),
    ...(deep ? { peers: () => bgpViewRelation(asn.value, 'peers') } : {}),
    ...(deep ? { upstreams: () => bgpViewRelation(asn.value, 'upstreams') } : {}),
    ...(deep ? { exchanges: () => bgpViewIxs(asn.value) } : {}),
  });

  return {
    query: { type: 'asn', value: asn.label, number: asn.value, depth: options.depth ?? 'standard' },
    public: true,
    registry: data.registry,
    profile: data.profile,
    overview: data.overview,
    network: data.network,
    prefixes: data.prefixes,
    peers: data.peers ?? null,
    upstreams: data.upstreams ?? null,
    exchanges: data.exchanges ?? null,
    contacts: contacts(data),
    assessment: assess(asn, data),
    pivots: pivots(asn.value),
    sources,
  };
}

/* ------------------------------------------------------------------ sources */

/** The registry record: who the number is legally allocated to. */
async function registryRecord(number) {
  const body = await rdap.lookup('autnum', number);
  const roles = rdap.entitiesByRole(body.entities);

  return {
    handle: body.handle ?? null,
    name: body.name ?? null,
    type: body.type ?? null,
    country: body.country ?? null,
    startAutnum: body.startAutnum ?? null,
    endAutnum: body.endAutnum ?? null,
    registered: rdap.eventDate(body.events, 'registration'),
    updated: rdap.eventDate(body.events, 'last changed'),
    status: body.status ?? [],
    registrant: roles.registrant ?? roles.administrative ?? null,
    abuseContact: roles.abuse ?? null,
    technical: roles.technical ?? null,
    remarks: rdap.remarkText(body.remarks).slice(0, 6),
  };
}

/** BGPView's normalised profile: the same shape across all five RIRs. */
async function bgpViewAsn(number) {
  const body = await getJson(`https://api.bgpview.io/asn/${number}`, {
    source: 'api.bgpview.io',
    timeout: 9000,
  });
  if (body.status !== 'ok') throw new Error(`BGPView has no record for AS${number}`);

  const d = body.data ?? {};
  return {
    name: d.name ?? null,
    description: d.description_short ?? null,
    descriptionFull: (d.description_full ?? []).slice(0, 4),
    country: d.country_code ?? null,
    website: d.website ?? null,
    rir: d.rir_allocation?.rir_name ?? null,
    allocated: d.rir_allocation?.date_allocated?.slice(0, 10) ?? null,
    lookingGlass: d.looking_glass ?? null,
    trafficEstimation: d.traffic_estimation ?? null,
    trafficRatio: d.traffic_ratio ?? null,
    ownerAddress: (d.owner_address ?? []).filter(Boolean).join(', ') || null,
    // Abuse and technical addresses published against the AS itself, which are
    // often maintained when the netblock-level ones are not.
    abuseContacts: (d.email_contacts ?? []).filter((e) => /abuse/i.test(e)),
    emailContacts: (d.email_contacts ?? []).slice(0, 6),
    abuseAddresses: (d.abuse_contacts ?? []).slice(0, 6),
  };
}

/** RIPEstat's AS overview: announcement status and holder, from the routing view. */
async function ripeOverview(number) {
  const body = await getJson(
    `https://stat.ripe.net/data/as-overview/data.json?resource=AS${number}`,
    { source: 'stat.ripe.net', timeout: 9000 },
  );

  const d = body.data ?? {};
  return {
    holder: d.holder ?? null,
    // "Not announced" on a registered AS is worth noticing: the number exists
    // but nothing is being routed under it right now.
    announced: d.announced ?? null,
    type: d.type ?? null,
    block: d.block?.desc ?? null,
    resource: d.resource ?? null,
  };
}

/** Every prefix the AS announces — the full address footprint. */
async function bgpViewPrefixes(number) {
  const body = await getJson(`https://api.bgpview.io/asn/${number}/prefixes`, {
    source: 'api.bgpview.io',
    timeout: 12000,
  });
  if (body.status !== 'ok') throw new Error(`BGPView has no prefix data for AS${number}`);

  const shape = (list) => (list ?? []).map((p) => ({
    prefix: p.prefix,
    name: p.name ?? null,
    description: p.description ?? null,
    country: p.country_code ?? null,
    parent: p.parent?.prefix ?? null,
  }));

  const v4 = shape(body.data?.ipv4_prefixes);
  const v6 = shape(body.data?.ipv6_prefixes);

  return {
    ipv4Count: v4.length,
    ipv6Count: v6.length,
    // Rough size of the announced space, which is the honest measure of how big
    // a network is — prefix *count* is not, since a /16 and a /24 both count one.
    ipv4Addresses: v4.reduce((total, p) => total + 2 ** (32 - Number(p.prefix.split('/')[1] || 32)), 0),
    ipv4: v4.slice(0, 60),
    ipv6: v6.slice(0, 40),
    truncated: v4.length > 60 || v6.length > 40,
  };
}

/**
 * Peers or upstreams.
 *
 * Upstreams are the networks that carry this one's traffic to the rest of the
 * internet — the parties with a commercial relationship and, for a network
 * behaving badly, the only effective place to complain.
 */
async function bgpViewRelation(number, relation) {
  const body = await getJson(`https://api.bgpview.io/asn/${number}/${relation}`, {
    source: 'api.bgpview.io',
    timeout: 12000,
  });
  if (body.status !== 'ok') throw new Error(`BGPView has no ${relation} for AS${number}`);

  const shape = (list) => (list ?? []).map((entry) => ({
    asn: `AS${entry.asn}`,
    name: entry.name ?? null,
    description: entry.description ?? null,
    country: entry.country_code ?? null,
  }));

  const v4 = shape(body.data?.ipv4_upstreams ?? body.data?.ipv4_peers);
  const v6 = shape(body.data?.ipv6_upstreams ?? body.data?.ipv6_peers);

  // The two families overlap heavily; one merged list is what a reader wants.
  const merged = [...v4, ...v6].filter(
    (entry, i, all) => all.findIndex((other) => other.asn === entry.asn) === i,
  );

  return { count: merged.length, networks: merged.slice(0, 40), truncated: merged.length > 40 };
}

/** Internet exchanges the AS is present at — physical locations it operates in. */
async function bgpViewIxs(number) {
  const body = await getJson(`https://api.bgpview.io/asn/${number}/ixs`, {
    source: 'api.bgpview.io',
    timeout: 10000,
  });
  if (body.status !== 'ok') throw new Error(`BGPView has no exchange data for AS${number}`);

  const exchanges = (body.data ?? []).map((ix) => ({
    name: ix.name ?? null,
    fullName: ix.name_full ?? null,
    country: ix.country_code ?? null,
    city: ix.city ?? null,
    speedMbps: ix.speed ?? null,
  }));

  return {
    count: exchanges.length,
    exchanges: exchanges.slice(0, 30),
    // Exchange presence is the closest thing to a physical footprint an AS has.
    countries: [...new Set(exchanges.map((e) => e.country).filter(Boolean))],
    cities: [...new Set(exchanges.map((e) => e.city).filter(Boolean))].slice(0, 20),
  };
}

/** The operator's own description of the network. */
async function peeringDb(number) {
  const body = await getJson(`https://www.peeringdb.com/api/net?asn=${number}`, {
    source: 'peeringdb.com',
    timeout: 9000,
  });

  const net = body.data?.[0];
  if (!net) throw new Error(`PeeringDB has no record for AS${number}`);

  return {
    name: net.name ?? null,
    alsoKnownAs: net.aka || null,
    website: net.website || null,
    networkType: net.info_type || null,
    scope: net.info_scope || null,
    trafficLevels: net.info_traffic || null,
    ratios: net.info_ratio || null,
    peeringPolicy: net.policy_general || null,
    policyUrl: net.policy_url || null,
    prefixesV4: net.info_prefixes4 ?? null,
    prefixesV6: net.info_prefixes6 ?? null,
    exchangeCount: net.ix_count ?? null,
    facilityCount: net.fac_count ?? null,
    irrAsSet: net.irr_as_set || null,
    lookingGlass: net.looking_glass || null,
    nocContact: net.poc_email || null,
    notes: (net.notes ?? '').slice(0, 400) || null,
    peeringDbUrl: `https://www.peeringdb.com/net/${net.id}`,
  };
}

/**
 * Every route to a human, gathered from the three registries that hold one.
 *
 * This is the practical output of an AS lookup. Where a netblock's RDAP record
 * is stale or redacted, the AS-level abuse address and the operator's published
 * NOC contact usually are not.
 */
function contacts(data) {
  const found = [];
  const add = (value, source, role) => {
    if (!value) return;
    const clean = String(value).trim();
    if (!clean || found.some((c) => c.value.toLowerCase() === clean.toLowerCase())) return;
    found.push({ value: clean, source, role });
  };

  add(data.registry?.abuseContact?.email, 'RDAP abuse contact', 'abuse');
  add(data.registry?.technical?.email, 'RDAP technical contact', 'technical');
  add(data.registry?.registrant?.email, 'RDAP registrant', 'registrant');
  for (const email of data.profile?.abuseAddresses ?? []) add(email, 'BGPView abuse', 'abuse');
  for (const email of data.profile?.emailContacts ?? []) {
    add(email, 'BGPView contact', /abuse/i.test(email) ? 'abuse' : 'general');
  }
  add(data.network?.nocContact, 'PeeringDB NOC', 'noc');

  const rank = { abuse: 0, noc: 1, technical: 2, registrant: 3, general: 4 };
  return found.sort((a, b) => (rank[a.role] ?? 9) - (rank[b.role] ?? 9)).slice(0, 12);
}

/* --------------------------------------------------------------- assessment */

function assess(asn, data) {
  const findings = [];
  const name = data.profile?.name ?? data.overview?.holder ?? data.registry?.name;

  findings.push({
    level: 'info',
    title: `${asn.label}${name ? ` — ${name}` : ''}`,
    detail: [
      data.profile?.description,
      data.profile?.country ? `registered in ${data.profile.country}` : null,
      data.profile?.rir ? `allocated by ${data.profile.rir}` : null,
      data.profile?.allocated ? `on ${data.profile.allocated}` : null,
    ].filter(Boolean).join(' · ') || 'No descriptive record was returned.',
  });

  if (data.overview && data.overview.announced === false) {
    findings.push({
      level: 'warn',
      title: 'Registered but not currently announced',
      detail: 'The AS number is allocated, but nothing is being routed under it right now. That is normal for a reserve or newly-issued number, and is also what a dormant or reclaimed network looks like.',
    });
  }

  const prefixes = data.prefixes;
  if (prefixes) {
    findings.push({
      level: 'info',
      title: `Announces ${prefixes.ipv4Count} IPv4 and ${prefixes.ipv6Count} IPv6 prefixes`,
      detail: `Roughly ${prefixes.ipv4Addresses.toLocaleString()} IPv4 addresses. Prefix count alone is misleading — a /16 and a /24 each count once — so the address total is the fairer measure of size.`,
    });
  }

  if (data.upstreams?.count) {
    findings.push({
      level: 'info',
      title: `${data.upstreams.count} upstream transit provider(s)`,
      detail: data.upstreams.networks.slice(0, 8).map((n) => `${n.asn} ${n.name ?? ''}`.trim()).join(', ')
        + '. These networks carry this AS to the rest of the internet, so they hold a contract with its operator and are the effective place to escalate abuse.',
    });
    if (data.upstreams.count === 1) {
      findings.push({
        level: 'info',
        title: 'Single-homed',
        detail: 'Only one upstream, so this network has no redundancy and is entirely dependent on that one provider — which also means one party can disconnect it.',
      });
    }
  }

  if (data.exchanges?.count) {
    findings.push({
      level: 'info',
      title: `Present at ${data.exchanges.count} internet exchange(s)`,
      detail: `${data.exchanges.cities.slice(0, 8).join(', ')}. Exchange presence is the closest thing an AS has to a physical footprint: equipment in those buildings, in those countries.`,
    });
  }

  const contactList = contacts(data);
  const abuse = contactList.filter((c) => c.role === 'abuse');
  if (abuse.length) {
    findings.push({
      level: 'ok',
      title: 'Abuse contact published',
      detail: abuse.map((c) => `${c.value} (${c.source})`).join(', '),
    });
  } else {
    findings.push({
      level: 'warn',
      title: 'No abuse contact found',
      detail: 'Neither the registry record nor the operator publishes an abuse address. RIRs require one, so an absence usually means a stale or deliberately unmaintained record.',
    });
  }

  if (data.network) {
    findings.push({
      level: 'info',
      title: 'Operator profile in PeeringDB',
      detail: [data.network.networkType, data.network.scope, data.network.trafficLevels,
        data.network.peeringPolicy ? `${data.network.peeringPolicy} peering` : null]
        .filter(Boolean).join(' · ')
        + '. PeeringDB entries are maintained by the operator, so this is how the network describes itself to its peers.',
    });
  } else {
    findings.push({
      level: 'info',
      title: 'No PeeringDB entry',
      detail: 'The operator has not registered the network with PeeringDB. Common for end-user networks and enterprises; unusual for a transit or content provider.',
    });
  }

  if (data.registry?.registered) {
    findings.push({
      level: 'info',
      title: `Registered ${data.registry.registered.slice(0, 10)}`,
      detail: `Held by ${data.registry.registrant?.organization ?? data.registry.registrant?.name ?? data.registry.name ?? 'an undisclosed entity'}`
        + `${data.registry.country ? ` in ${data.registry.country}` : ''}.`,
    });
  }

  return findings;
}

function pivots(number) {
  return [
    { label: 'BGP.tools', url: `https://bgp.tools/as/${number}` },
    { label: 'BGPView', url: `https://bgpview.io/asn/${number}` },
    { label: 'RIPEstat', url: `https://stat.ripe.net/AS${number}` },
    { label: 'PeeringDB', url: `https://www.peeringdb.com/search?q=AS${number}` },
    { label: 'Hurricane Electric', url: `https://bgp.he.net/AS${number}` },
    { label: 'Shodan', url: `https://www.shodan.io/search?query=asn%3AAS${number}` },
    { label: 'Censys', url: `https://search.censys.io/search?resource=hosts&q=autonomous_system.asn%3A${number}` },
    { label: 'RADb IRR', url: `https://www.radb.net/query?keywords=AS${number}` },
    { label: 'Spamhaus ASN drop', url: 'https://www.spamhaus.org/drop/' },
    { label: 'CAIDA AS rank', url: `https://asrank.caida.org/asns/${number}` },
  ];
}
