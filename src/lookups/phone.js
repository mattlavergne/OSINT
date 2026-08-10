/**
 * Phone number intelligence.
 *
 * GhostTrack's phone tracker was a thin wrapper over the `phonenumbers` Python
 * port. This does the same core work with Google's libphonenumber rules, then
 * adds the honesty the original lacked: number portability means carrier data
 * describes the *original allocation*, not necessarily today's operator, and
 * "location" means the number's assigned area — not where the handset is. Both
 * caveats are returned in the payload so the UI can state them.
 */

import { parsePhoneNumberWithError, ParseError, getExampleNumber } from 'libphonenumber-js/max';
import examples from 'libphonenumber-js/mobile/examples';
import { parsePhoneInput, ValidationError } from '../lib/validate.js';
import { getJson, getText } from '../lib/http.js';

/** Human labels for libphonenumber's number types. */
const TYPE_LABELS = {
  MOBILE: 'Mobile',
  FIXED_LINE: 'Fixed line',
  FIXED_LINE_OR_MOBILE: 'Fixed line or mobile',
  PREMIUM_RATE: 'Premium rate',
  TOLL_FREE: 'Toll free',
  SHARED_COST: 'Shared cost',
  VOIP: 'VoIP',
  PERSONAL_NUMBER: 'Personal number',
  PAGER: 'Pager',
  UAN: 'Universal access number',
  VOICEMAIL: 'Voicemail',
};

const TYPE_NOTES = {
  VOIP: 'VoIP numbers are cheap and disposable, and are commonly used to evade attribution.',
  PERSONAL_NUMBER: 'A follow-me number that forwards to another line; it does not identify a device.',
  PREMIUM_RATE: 'Calls to this number are billed at a premium — a common vector in wangiri callback fraud.',
  TOLL_FREE: 'Toll-free numbers belong to organisations rather than individuals.',
  PAGER: 'Pager allocations are largely legacy ranges.',
  FIXED_LINE_OR_MOBILE: 'This range serves both fixed and mobile lines, so the type cannot be narrowed further.',
};

/**
 * Operating company numbers whose names mean "this is a VoIP or wholesale
 * number", not "this is a phone line in a building".
 *
 * These carriers sell numbers by the thousand through APIs with no address
 * verification, which is why they sit behind most spoofed and disposable
 * numbers. The LERG names the block holder outright, so this is a direct read
 * rather than an inference from the number's shape.
 */
const WHOLESALE_CARRIERS = [
  'bandwidth', 'twilio', 'telnyx', 'onvoy', 'peerless', 'inteliquent',
  'level 3', 'lumen', 'sinch', 'vonage', 'nexmo', 'plivo', 'voxbone',
  'flowroute', 'thinq', 'commio', 'teli', 'skype', 'microsoft', 'google voice',
  'neutral tandem', 'transbeam', 'ringcentral', 'zoom', 'dialpad', '8x8',
  'magicjack', 'textnow', 'pinger', 'bandwith', 'iristel', 'distributel',
  'voip', 'telecom systems', 'wholesale carrier', 'ymax', 'sipwise',
];

export async function lookupPhone(input, region, loadData, env = {}, options = {}) {
  const { value, region: hintRegion } = parsePhoneInput(input, region);

  let phone;
  try {
    phone = parsePhoneNumberWithError(value, hintRegion);
  } catch (err) {
    if (err instanceof ParseError) {
      throw new ValidationError(explainParseError(err.message, value, hintRegion));
    }
    throw err;
  }

  const valid = phone.isValid();
  const national = phone.nationalNumber;
  const callingCode = phone.countryCallingCode;
  const e164Digits = `${callingCode}${national}`;

  // Reference data is fetched per calling code, so a lookup only ever pulls the
  // shard it needs. All three are optional enrichments — a failure here must not
  // fail the whole lookup.
  //
  // Note the two key spaces: the geocoding and carrier shards are keyed by the
  // *national* significant number (the calling code is already the filename),
  // while the timezone map is keyed by the full E.164 digits.
  const [geo, carrier, timezones] = await Promise.all([
    lookupPrefix(loadData, `geo/${callingCode}.json`, national),
    lookupPrefix(loadData, `carrier/${callingCode}.json`, national),
    lookupPrefix(loadData, 'timezones.json', e164Digits),
  ]);

  const type = phone.getType() ?? null;

  // Two name sources, run together:
  //  - OpenStreetMap: free and keyless, but only ever covers mapped businesses
  //    and public POIs. Never individuals.
  //  - Twilio CNAM: the carrier caller-ID database. Metered, and the only
  //    source that can name a subscriber.
  const isNanp = callingCode === '1' && valid;

  // `offline` turns off every network-backed enrichment, leaving only
  // libphonenumber and the bundled reference data. The offline unit tests rely
  // on it: without it they would depend on six third-party services being
  // reachable, which is neither fast nor a test of this code.
  const live_ = !options.offline;

  const [places, filings, footprint, live, lerg, encyclopedia] = await Promise.all([
    live_ && valid ? openStreetMap(phone).catch((err) => ({ error: err.message })) : null,
    live_ && valid ? secEdgar(phone).catch((err) => ({ error: err.message })) : null,
    live_ && valid && env.BRAVE_SEARCH_API_KEY
      ? searchFootprint(phone, env.BRAVE_SEARCH_API_KEY).catch((err) => ({ error: err.message }))
      : null,
    live_ && env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN
      ? twilioLookup(phone.format('E.164'), env).catch((err) => ({ error: err.message }))
      : null,
    live_ && isNanp ? numberingPlan(phone).catch((err) => ({ error: err.message })) : null,
    live_ && valid ? wikipediaMentions(phone).catch((err) => ({ error: err.message })) : null,
  ]);

  const osm = places && !places.error ? places : null;
  const sec = filings && !filings.error ? filings : null;
  const search = footprint && !footprint.error ? footprint : null;
  const cnam = live && !live.error ? live : null;
  const plan = lerg && !lerg.error ? lerg : null;
  const wiki = encyclopedia && !encyclopedia.error ? encyclopedia : null;

  return {
    query: { type: 'phone', value, region: hintRegion ?? null, depth: options.depth ?? 'standard' },
    valid,
    possible: phone.isPossible(),
    country: phone.country ?? null,
    countryCallingCode: `+${callingCode}`,
    nationalNumber: national,
    numberType: type,
    numberTypeLabel: type ? (TYPE_LABELS[type] ?? type) : null,
    numberTypeNote: type ? (TYPE_NOTES[type] ?? null) : null,
    formats: {
      e164: phone.format('E.164'),
      international: phone.formatInternational(),
      national: phone.formatNational(),
      rfc3966: phone.format('RFC3966'),
      uri: phone.getURI(),
    },
    location: geo ?? null,
    carrier: carrier ?? null,
    // North American Numbering Plan block data: the rate centre, the switch the
    // block homes on, and the company the block is allocated to.
    numberingPlan: plan,
    // Live, metered enrichment. Null unless Twilio credentials are configured.
    identity: cnam,
    identityError: live?.error ?? null,
    // Free, keyless business attribution from OpenStreetMap.
    places: osm?.places ?? [],
    // US public companies, from SEC EDGAR full-text search.
    filings: sec?.matched ? sec : null,
    // Search-engine footprint. Null unless a Brave key is configured.
    search,
    // Wikipedia articles that print this number.
    encyclopedia: wiki?.matched ? wiki : null,
    // Every name candidate, ranked and labelled with where it came from.
    attribution: attribution({ osm, sec, search, cnam, wiki }),
    riskProfile: riskProfile(type, plan, cnam, carrier),
    timezones: Array.isArray(timezones) ? timezones : timezones ? [timezones] : [],
    localTime: localTimes(Array.isArray(timezones) ? timezones : []),
    // Every written form of the number, for searching by hand where no API
    // reaches. Search engines index each of these differently.
    variants: writtenForms(phone),
    caveats: caveats(valid, geo, carrier, type, cnam, osm, sec, search, plan),
    example: exampleFor(phone.country),
    assessment: assess(phone, valid, type, carrier, cnam, osm, sec, plan, wiki),
    pivots: pivots(phone.format('E.164')),
    sources: {
      libphonenumber: { ok: true },
      referenceData: { ok: geo !== undefined || carrier !== undefined },
      ...(places ? { openStreetMap: places.error ? { ok: false, error: places.error } : { ok: true } } : {}),
      ...(filings ? { secEdgar: filings.error ? { ok: false, error: filings.error } : { ok: true } } : {}),
      ...(footprint ? { searchFootprint: footprint.error ? { ok: false, error: footprint.error } : { ok: true } } : {}),
      ...(live ? { twilioLookup: live.error ? { ok: false, error: live.error } : { ok: true } } : {}),
      ...(lerg ? { numberingPlan: lerg.error ? { ok: false, error: lerg.error } : { ok: true } } : {}),
      ...(encyclopedia ? { wikipedia: encyclopedia.error ? { ok: false, error: encyclopedia.error } : { ok: true } } : {}),
    },
  };
}

/* ------------------------------------------------- North American numbering */

/**
 * NANP block data from the Local Calling Guide.
 *
 * This is the single biggest free upgrade available for a US or Canadian
 * number. The bundled libphonenumber dataset gives a coarse area name and the
 * carrier a range was allocated to years ago. The LERG — which the Local
 * Calling Guide republishes as a keyless XML API — gives the *rate centre*, the
 * physical central-office switch the block homes on (by CLLI code, switch name
 * and model), the LATA, the operating company number, and the rate centre's
 * own coordinates.
 *
 * For a landline that is a real geographic fix on a telephone exchange, not a
 * database's guess at a city. It is also the honest way to spot a VoIP number:
 * the block holder is named outright, and wholesale carriers are unmistakable.
 */
async function numberingPlan(phone) {
  const national = String(phone.nationalNumber);
  if (national.length !== 10) throw new Error('NANP lookups need a 10-digit national number');

  const npa = national.slice(0, 3);
  const nxx = national.slice(3, 6);

  const xml = await getText(
    `https://localcallingguide.com/xmlprefix.php?npa=${npa}&nxx=${nxx}`,
    { source: 'localcallingguide.com', timeout: 9000 },
  );

  // The response carries a large DTD before the data; read the fields directly
  // rather than pulling in an XML parser for eight elements.
  const field = (name) => {
    const match = xml.match(new RegExp(`<${name}>([^<]*)</${name}>`, 'i'));
    const value = match?.[1]?.trim();
    return value || null;
  };

  const company = field('company-name');
  if (!company && !field('rc')) throw new Error(`No LERG record for ${npa}-${nxx}`);

  const latitude = field('rc-lat') ? Number(field('rc-lat')) : null;
  const longitude = field('rc-lon') ? Number(field('rc-lon')) : null;
  const wholesale = WHOLESALE_CARRIERS.find((c) => (company ?? '').toLowerCase().includes(c)) ?? null;

  return {
    npa,
    nxx,
    // The rate centre is the billing/geographic unit a landline belongs to —
    // considerably finer than a city for large metros.
    rateCentre: field('rc'),
    region: field('region'),
    lata: field('lata'),
    // The CLLI code identifies one physical switch in one building.
    switchClli: field('switch'),
    switchName: field('switchname'),
    switchType: field('switchtype'),
    ocn: field('ocn'),
    company,
    // I = incumbent local exchange carrier, C = competitive, W = wireless.
    companyType: field('company-type'),
    incumbentCarrier: field('ilec-name'),
    // "A" means the whole 10,000-number block; a digit means a pooled
    // 1,000-number block, which is the modern norm and narrows the holder.
    blockIdentifier: field('x'),
    effectiveDate: field('effdate'),
    updated: field('udate')?.slice(0, 10) ?? null,
    latitude,
    longitude,
    mapUrl: latitude != null && longitude != null
      ? `https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}#map=13/${latitude}/${longitude}`
      : null,
    wholesaleCarrier: wholesale,
    note: 'Rate-centre and switch data describe where the number block is homed, which is where a landline physically terminates. A mobile or ported number keeps the block\'s identity but not its location.',
  };
}

/**
 * Wikipedia full-text search for the number.
 *
 * Narrow but occasionally decisive: an emergency line, a government department,
 * a broadcaster's phone-in, or a well-known company's switchboard is often
 * printed in an article, and the article names it unambiguously. Keyless, and
 * the MediaWiki search API handles quoted phrases properly.
 */
async function wikipediaMentions(phone) {
  const query = `insource:"${phone.formatInternational()}" OR insource:"${phone.formatNational()}"`;
  const body = await getJson(
    'https://en.wikipedia.org/w/api.php?action=query&list=search&format=json&origin=*'
      + `&srlimit=5&srsearch=${encodeURIComponent(query)}`,
    { source: 'en.wikipedia.org', timeout: 9000 },
  );

  const hits = body.query?.search ?? [];
  return {
    matched: hits.length > 0,
    articles: hits.map((hit) => ({
      title: hit.title,
      snippet: (hit.snippet ?? '').replace(/<[^>]+>/g, '').trim() || null,
      url: `https://en.wikipedia.org/wiki/${encodeURIComponent(hit.title.replace(/ /g, '_'))}`,
    })),
  };
}

/**
 * What kind of number is this, and how much should a name attached to it be
 * trusted?
 *
 * Type, block holder and caller ID each answer part of the question. Combining
 * them is what separates "a landline on a Verizon switch in Manhattan" from
 * "a number bought through an API twenty minutes ago".
 */
function riskProfile(type, plan, cnam, carrier) {
  const signals = [];
  let level = 'normal';

  if (plan?.wholesaleCarrier) {
    signals.push({
      signal: 'Wholesale block holder',
      detail: `The block is allocated to ${plan.company}, a carrier that sells numbers programmatically. Numbers from these ranges are cheap, instantly provisioned, and are the ones most often used to evade attribution.`,
    });
    level = 'elevated';
  }
  if (type === 'VOIP') {
    signals.push({ signal: 'VoIP line type', detail: 'libphonenumber classifies this range as VoIP, which has no fixed physical location by design.' });
    level = 'elevated';
  }
  if (type === 'PREMIUM_RATE') {
    signals.push({ signal: 'Premium rate', detail: 'Calls are billed at a premium. Callback requests to premium numbers are the wangiri fraud pattern.' });
    level = 'high';
  }
  if (plan?.companyType === 'C') {
    signals.push({ signal: 'Competitive carrier block', detail: 'The block belongs to a CLEC rather than the incumbent, which is normal but is also the usual route for VoIP resale.' });
  }
  if (cnam?.currentCarrier && carrier && cnam.currentCarrier !== carrier) {
    signals.push({ signal: 'Ported', detail: `The number has moved from ${carrier} to ${cnam.currentCarrier}, so allocation data no longer describes the current operator.` });
  }
  if (plan?.companyType === 'I' && type === 'FIXED_LINE') {
    signals.push({ signal: 'Incumbent landline', detail: `A fixed line on ${plan.incumbentCarrier ?? plan.company}'s own switch. This is the most location-meaningful kind of number there is.` });
  }
  if (!signals.length) {
    signals.push({ signal: 'Nothing unusual', detail: 'Nothing about the line type or block allocation stands out.' });
  }

  return { level, signals };
}

/**
 * Every written form of the number.
 *
 * Search engines, forums and leaked datasets each write numbers differently,
 * and a search for one spelling misses the rest. Listing them is the difference
 * between "no results" and a result the searcher had to guess their way to.
 */
function writtenForms(phone) {
  const e164 = phone.format('E.164');
  const national = phone.formatNational();
  const international = phone.formatInternational();
  const digits = e164.replace('+', '');
  const nationalDigits = String(phone.nationalNumber);

  return [...new Set([
    e164,
    international,
    national,
    phone.format('RFC3966'),
    digits,
    nationalDigits,
    international.replace(/ /g, '-'),
    international.replace(/ /g, '.'),
    national.replace(/[()]/g, '').replace(/\s+/g, '-'),
    national.replace(/[()\s-]/g, ''),
    `00${digits}`,
    nationalDigits.length === 10
      ? `${nationalDigits.slice(0, 3)}.${nationalDigits.slice(3, 6)}.${nationalDigits.slice(6)}`
      : null,
  ].filter(Boolean))];
}

/* --------------------------------------------------------- open-data lookup */

/** Overpass mirrors, tried in order. The main instance is often busy. */
const OVERPASS_MIRRORS = [
  'https://overpass-api.de/api/interpreter',
  'https://overpass.kumi.systems/api/interpreter',
];

/**
 * Tags OSM stores a number under.
 *
 * `phone` and `contact:phone` carry the overwhelming majority. The rest are
 * split out because they are worth checking but must not slow the common case:
 * a business whose main line is recorded only as a fax or a mobile is invisible
 * without them, and those are exactly the records nobody else looks at.
 */
const OSM_PRIMARY_TAGS = ['phone', 'contact:phone'];
const OSM_SECONDARY_TAGS = ['contact:mobile', 'phone:mobile', 'fax', 'contact:fax'];

/**
 * Reverse-lookup a phone number against OpenStreetMap.
 *
 * This is a genuinely free, keyless way to put a *name* to a number — the catch
 * is that it only covers businesses and public POIs that someone has mapped,
 * never individuals. When it hits, it is high quality: the operator published
 * the number themselves and the data is open (ODbL).
 *
 * OSM stores numbers as free text with wildly inconsistent punctuation, and a
 * planet-wide regex scan times out, so the plausible spellings are generated
 * from libphonenumber's own formatters and matched exactly off Overpass's value
 * index. The public instances cost roughly a second per union clause, though,
 * so the naive query — every spelling against every tag — is a minute of wall
 * time. The clauses are split into two groups by how likely they are to hit and
 * run in parallel against different mirrors: the common case answers in the
 * time one query would take, and the uncommon tags still get checked.
 */
async function openStreetMap(phone) {
  const pattern = spellingPattern(phoneSpellings(phone));

  const [first, second] = await Promise.allSettled([
    overpass(OSM_PRIMARY_TAGS, pattern, OVERPASS_MIRRORS),
    overpass(OSM_SECONDARY_TAGS, pattern, [...OVERPASS_MIRRORS].reverse()),
  ]);

  if (first.status === 'rejected' && second.status === 'rejected') {
    throw first.reason ?? second.reason;
  }

  const elements = [
    ...(first.status === 'fulfilled' ? first.value : []),
    ...(second.status === 'fulfilled' ? second.value : []),
  ];

  // The two queries can return the same object; identity is type plus id.
  const seen = new Set();
  const unique = elements.filter((e) => {
    const key = `${e.type}/${e.id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const places = describePlaces(unique);
  return { matched: places.length > 0, places, partial: first.status === 'rejected' || second.status === 'rejected' };
}

/**
 * One anchored alternation covering every spelling.
 *
 * This is the difference between a query that answers and one that times out.
 * Overpass has no value index for arbitrary tags, so `nwr["phone"="x"]` scans
 * every object carrying a `phone` tag — and a union of eight such clauses scans
 * the same data eight times. Folding the spellings into a single value regex
 * means one scan per key instead of one per spelling.
 */
function spellingPattern(spellings) {
  const escaped = spellings.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  return `^(${escaped.join('|')})$`;
}

/** Run one Overpass union over a set of keys, trying each mirror in turn. */
async function overpass(keys, valuePattern, mirrors) {
  if (!keys.length) return [];

  // The pattern is going inside an Overpass QL string literal, which does its
  // own backslash unescaping before the regex engine ever sees the value. A
  // regex `\+` written straight into the literal arrives as a bare `+` and the
  // whole query is rejected as an invalid regular expression, so every
  // backslash has to survive one extra round of unescaping.
  const literal = valuePattern.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const clauses = keys.map((key) => `nwr["${key}"~"${literal}"];`).join('');
  const query = `[out:json][timeout:45];(${clauses});out center tags;`;

  let lastError;
  for (const endpoint of mirrors) {
    try {
      const body = await getJson(endpoint, {
        source: new URL(endpoint).hostname,
        method: 'POST',
        // A planet-wide scan on a busy public instance needs real headroom;
        // a timeout here loses the only free source that names a business.
        timeout: 18000,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: `data=${encodeURIComponent(query)}`,
      });
      return body.elements ?? [];
    } catch (err) {
      lastError = err;
      // 429 means this source address has spent its quota, not that the query
      // was wrong. Worth saying plainly: on shared egress it is the single most
      // common reason this panel is empty, and retrying the other mirror with
      // the same address will usually fail the same way.
      if (err.status === 429) {
        lastError = new Error(
          'Overpass rate-limited this source address (HTTP 429). The public instances meter by IP, '
          + 'and shared egress — a Worker, a VPN, a datacenter — is frequently exhausted by unrelated traffic.',
        );
      }
    }
  }
  throw lastError ?? new Error('No Overpass mirror responded');
}

/**
 * Turn Overpass elements into place records.
 *
 * The social handles are worth as much as the address: an OSM entry that
 * carries a Facebook or Instagram account hands you a verified link between a
 * phone number and a live profile, which is a chain no other free source here
 * completes.
 */
function describePlaces(elements) {
  const allTags = [...OSM_PRIMARY_TAGS, ...OSM_SECONDARY_TAGS];

  return elements
    .filter((e) => e.tags?.name)
    .map((e) => {
      const t = e.tags;
      const latitude = e.lat ?? e.center?.lat ?? null;
      const longitude = e.lon ?? e.center?.lon ?? null;

      const socials = [
        ['Facebook', t.facebook ?? t['contact:facebook']],
        ['Instagram', t.instagram ?? t['contact:instagram']],
        ['X / Twitter', t.twitter ?? t['contact:twitter']],
        ['LinkedIn', t.linkedin ?? t['contact:linkedin']],
        ['YouTube', t.youtube ?? t['contact:youtube']],
      ].filter(([, handle]) => handle).map(([platform, handle]) => ({ platform, handle }));

      return {
        name: t.name,
        category: t.amenity ?? t.shop ?? t.office ?? t.tourism ?? t.healthcare ?? t.craft ?? t.leisure ?? null,
        operator: t.operator ?? null,
        brand: t.brand ?? null,
        address: [t['addr:housenumber'], t['addr:street'], t['addr:city'], t['addr:postcode']]
          .filter(Boolean).join(' ') || null,
        website: t.website ?? t['contact:website'] ?? null,
        email: t.email ?? t['contact:email'] ?? null,
        openingHours: t.opening_hours ?? null,
        socials,
        // Which tag matched says whether this is the main line or a fax.
        matchedTag: allTags.find((tag) => t[tag]) ?? null,
        phone: t.phone ?? t['contact:phone'] ?? null,
        // Coordinates make this the only source here that puts a number on a
        // map with street-level accuracy.
        latitude,
        longitude,
        mapUrl: latitude != null
          ? `https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}#map=18/${latitude}/${longitude}`
          : null,
        osmUrl: `https://www.openstreetmap.org/${e.type}/${e.id}`,
      };
    })
    .slice(0, 10);
}

/**
 * Plausible written forms of a number, derived from libphonenumber's canonical
 * formats rather than hardcoded per-country patterns.
 */
function phoneSpellings(phone) {
  const intl = phone.formatInternational();       // "+1 212 343 3355"
  const national = phone.formatNational();        // "(212) 343-3355"
  const e164 = phone.format('E.164');             // "+12123433355"
  const cc = `+${phone.countryCallingCode}`;

  // "+1 212 343 3355" -> "+1 212-343-3355": keep the space after the calling
  // code, hyphenate the rest. This is the single most common OSM spelling.
  const firstSpace = intl.indexOf(' ');
  const mixed = firstSpace === -1
    ? intl
    : intl.slice(0, firstSpace + 1) + intl.slice(firstSpace + 1).replace(/ /g, '-');

  return [...new Set([
    intl,
    mixed,
    intl.replace(/ /g, '-'),
    e164,
    national,
    `${cc} ${national}`,
    national.replace(/[()]/g, '').replace(/\s+/g, '-'),
    // Written without any separator at all, which is common in bulk imports.
    `${cc}${String(phone.nationalNumber)}`,
  ])].filter(Boolean);
}

/* ------------------------------------------------------------- attribution */

/**
 * Merge every name candidate into one ranked list.
 *
 * The sources differ enormously in what a hit actually proves, so each
 * candidate carries its origin and a confidence band rather than being blended
 * into a single answer:
 *
 *   high    the entity filed or published this number as its own
 *   medium  a maintained public dataset lists it against this entity
 *   low     a search engine surfaced it; unverified
 */
function attribution({ osm, sec, search, cnam, wiki }) {
  const names = [];
  const add = (value, source, confidence, detail = null) => {
    if (!value) return;
    const clean = String(value).trim();
    if (clean.length < 2 || clean.length > 120) return;
    const existing = names.find((n) => n.value.toLowerCase() === clean.toLowerCase());
    if (existing) {
      // Corroboration across independent sources is the strongest signal here.
      existing.corroboration = (existing.corroboration ?? 1) + 1;
      return;
    }
    names.push({ value: clean, source, confidence, detail, corroboration: 1 });
  };

  for (const company of sec?.companies ?? []) {
    add(
      company.name,
      'SEC EDGAR',
      company.confirmed ? 'high' : 'low',
      company.confirmed
        ? `Filed as the company's own number${company.location ? ` · ${company.location}` : ''}`
        : 'Mentioned in filings, but not the number on their EDGAR profile',
    );
  }

  if (cnam?.callerName) {
    add(cnam.callerName, 'CNAM caller ID', 'high',
      cnam.callerType === 'BUSINESS' ? 'Carrier business listing' : 'Carrier subscriber listing');
  }

  for (const place of osm?.places ?? []) {
    add(place.name, 'OpenStreetMap', 'medium',
      [place.category, place.address].filter(Boolean).join(' · ') || null);
    // The operator tag names the company behind a branded location, which is
    // often the entity you actually want rather than the shop's trading name.
    if (place.operator && place.operator !== place.name) {
      add(place.operator, 'OpenStreetMap operator', 'medium', `Operator of ${place.name}`);
    }
  }

  for (const article of wiki?.articles ?? []) {
    add(article.title, 'Wikipedia', 'medium', 'An article printing this number');
  }

  for (const candidate of search?.candidateNames ?? []) {
    add(candidate.value, 'Search results', 'low',
      `Appears in ${candidate.mentions} of the top search results`);
  }

  const rank = { high: 0, medium: 1, low: 2 };
  names.sort((a, b) =>
    rank[a.confidence] - rank[b.confidence] || b.corroboration - a.corroboration);

  return {
    names,
    // The honest headline: only promote a name the number's owner published.
    best: names.find((n) => n.confidence === 'high') ?? names[0] ?? null,
    checked: [
      osm ? 'OpenStreetMap' : null,
      sec ? 'SEC EDGAR' : null,
      wiki ? 'Wikipedia' : null,
      search ? 'Search results' : null,
      cnam ? 'CNAM caller ID' : null,
    ].filter(Boolean),
  };
}

/* ------------------------------------------------------------ SEC filings */

/** Digits only, for comparing numbers written in different styles. */
const digitsOf = (value) => String(value ?? '').replace(/\D/g, '');

/**
 * SEC EDGAR full-text search.
 *
 * Every US public company files its principal phone number with the SEC, and
 * EDGAR's full-text index is free, keyless and official. Narrow coverage by
 * design — US registrants only — but when it hits, the attribution is as
 * authoritative as it gets: a number a company filed under penalty of perjury.
 *
 * A full-text hit alone is weak evidence, since the number may appear in a
 * filing for any reason (an agent, a counterparty, a target). So each candidate
 * company is confirmed against the phone on its own EDGAR profile, and only an
 * exact digit match is reported as the filer's own number.
 */
async function secEdgar(phone) {
  // Two spellings is enough: EDGAR normalises little, but filings overwhelmingly
  // use the national format, with E.164 as the occasional alternative.
  const spellings = [phone.formatNational(), phone.format('E.164')];
  const wanted = digitsOf(phone.format('E.164'));

  for (const spelling of spellings) {
    let body;
    try {
      body = await getJson(
        `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent(`"${spelling}"`)}`,
        { source: 'efts.sec.gov', timeout: 8000 },
      );
    } catch {
      continue;
    }

    const hits = body.hits?.hits ?? [];
    if (!hits.length) continue;

    const ciks = [...new Set(hits.flatMap((h) => h._source?.ciks ?? []))].slice(0, 3);
    const companies = (await Promise.all(ciks.map((cik) => secCompany(cik, wanted))))
      .filter(Boolean);

    if (companies.length) {
      return {
        matched: true,
        totalFilings: body.hits?.total?.value ?? hits.length,
        companies,
      };
    }
  }

  return { matched: false, totalFilings: 0, companies: [] };
}

async function secCompany(cik, wantedDigits) {
  const padded = String(cik).padStart(10, '0');
  let body;
  try {
    body = await getJson(`https://data.sec.gov/submissions/CIK${padded}.json`, {
      source: 'data.sec.gov',
      timeout: 8000,
    });
  } catch {
    return null;
  }

  const business = body.addresses?.business ?? {};
  // Compare on the last 10 digits so a filed number without a country code
  // still matches an E.164 query.
  const filed = digitsOf(body.phone);
  const confirmed = filed.length >= 7 && wantedDigits.endsWith(filed.slice(-10));

  return {
    name: body.name ?? null,
    cik: padded,
    phone: body.phone ?? null,
    // "Filed by this company" vs "merely mentioned in its filings".
    confirmed,
    industry: body.sicDescription ?? null,
    tickers: body.tickers ?? [],
    location: [business.city, business.stateOrCountry].filter(Boolean).join(', ') || null,
    edgarUrl: `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=${padded}`,
  };
}

/* --------------------------------------------------------- search footprint */

/**
 * Run the search a human would run, and return what comes back.
 *
 * This is the single highest-yield technique in phone OSINT, and it is what
 * PhoneInfoga automates only halfway — it builds dork URLs and leaves the
 * searching to you. Running it server-side and surfacing titles and snippets
 * closes that gap.
 *
 * Requires a Brave Search API key. There is no keyless option that works from a
 * Worker: DuckDuckGo's HTML endpoint returns a bot challenge to datacenter
 * addresses, its Instant Answer API has no results for phone numbers, and
 * public SearxNG instances serve a captcha. Brave's free tier covers 2,000
 * queries a month.
 */
async function searchFootprint(phone, key) {
  const query = `"${phone.formatNational()}" OR "${phone.format('E.164')}"`;

  const body = await getJson(
    `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=10`,
    {
      source: 'api.search.brave.com',
      timeout: 9000,
      headers: { 'x-subscription-token': key, accept: 'application/json' },
    },
  );

  const results = (body.web?.results ?? []).slice(0, 10).map((r) => ({
    title: r.title ?? null,
    url: r.url ?? null,
    // Brave marks the matched terms with <strong>; strip to plain text.
    snippet: (r.description ?? '').replace(/<[^>]+>/g, '').trim() || null,
    siteName: r.profile?.name ?? null,
  }));

  return {
    query,
    resultCount: results.length,
    results,
    candidateNames: nameCandidatesFrom(results),
  };
}

/**
 * Guess organisation names from result titles.
 *
 * Titles are mostly "<Name> | <tagline>" or "<Name> - <city>", so the leading
 * segment is usually the entity. A name that shows up across several
 * independent results is far more likely to be real than a one-off, so
 * candidates are ranked by how many results mention them.
 */
function nameCandidatesFrom(results) {
  const counts = new Map();

  for (const result of results) {
    if (!result.title) continue;
    const lead = result.title.split(/\s[|·—–-]\s|,\s/)[0].trim();

    // Directory and spam sites dominate these results and name nobody.
    if (/whitepages|truecaller|spokeo|yellowpages|numlookup|whocalled|phone|caller|scam|lookup|directory|reverse/i.test(lead)) continue;
    if (lead.length < 3 || lead.length > 60 || /^\d+$/.test(lead)) continue;

    const key = lead.toLowerCase();
    counts.set(key, { value: lead, count: (counts.get(key)?.count ?? 0) + 1 });
  }

  return [...counts.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
    .map((c) => ({ value: c.value, mentions: c.count }));
}

/* ----------------------------------------------------------- live enrichment */

/**
 * Twilio Lookup v2: CNAM caller name and line-type intelligence.
 *
 * `caller_name` is the carrier-maintained caller-ID record — a business name,
 * or a subscriber name for some US landlines. It is the only name source here
 * that is both authoritative and lawful to query; it is US-only and billed per
 * lookup. `line_type_intelligence` resolves the *current* carrier after number
 * portability, which is exactly what the bundled static dataset cannot do.
 */
async function twilioLookup(e164, env) {
  const credentials = btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`);
  const body = await getJson(
    `https://lookups.twilio.com/v2/PhoneNumbers/${encodeURIComponent(e164)}` +
      '?Fields=caller_name,line_type_intelligence',
    { source: 'lookups.twilio.com', timeout: 9000, headers: { authorization: `Basic ${credentials}` } },
  );

  const caller = body.caller_name ?? {};
  const line = body.line_type_intelligence ?? {};

  return {
    callerName: caller.caller_name ?? null,
    // "BUSINESS" or "CONSUMER" — worth surfacing, since it frames the name.
    callerType: caller.caller_type ?? null,
    currentCarrier: line.carrier_name ?? null,
    currentLineType: line.type ?? null,
    mobileCountryCode: line.mobile_country_code ?? null,
    mobileNetworkCode: line.mobile_network_code ?? null,
    valid: body.valid ?? null,
  };
}

/* -------------------------------------------------------------- reference data */

/**
 * Longest-prefix match against a prefix→value map, the same strategy Google's
 * own geocoder uses: try the full number, then drop a digit at a time until a
 * range matches or we run out of digits.
 */
async function lookupPrefix(loadData, path, digits) {
  if (typeof loadData !== 'function') return null;

  let table;
  try {
    table = await loadData(path);
  } catch {
    return null;
  }
  if (!table) return null;

  for (let length = digits.length; length > 0; length--) {
    const candidate = digits.slice(0, length);
    if (Object.hasOwn(table, candidate)) return table[candidate];
  }
  return null;
}

/* ---------------------------------------------------------------- derivations */

function localTimes(zones) {
  return zones.slice(0, 6).map((zone) => {
    try {
      const formatter = new Intl.DateTimeFormat('en-GB', {
        timeZone: zone,
        hour: '2-digit',
        minute: '2-digit',
        weekday: 'short',
        timeZoneName: 'short',
      });
      return { zone, time: formatter.format(new Date()) };
    } catch {
      return { zone, time: null };
    }
  });
}

function caveats(valid, geo, carrier, type, live, osm, sec, search, plan) {
  const notes = [];
  if (plan) {
    notes.push('Rate-centre and switch data describe where the *number block* is homed in the numbering plan. For a fixed line that is genuinely where the line terminates; for a mobile or ported number the block identity survives but the location does not.');
  }
  if (valid) {
    notes.push('Validity means the number matches the published numbering plan for its country. It does not mean the number is currently assigned or in service.');
  }
  if (geo) {
    notes.push('Location is the geographic area the number range is allocated to — not the current position of the device. Mobile numbers travel with their owner.');
  }
  if (carrier) {
    notes.push('Carrier reflects the operator the range was originally allocated to. Number portability means the number may have since moved to a different network.');
  }
  if (!geo && !carrier && valid) {
    notes.push('No geographic or carrier data is published for this range. Mobile ranges in many countries are allocated nationally rather than by region.');
  }
  if (type === 'VOIP') {
    notes.push('VoIP numbers have no fixed physical location by design.');
  }
  if (live?.callerName) {
    notes.push('Caller ID names are supplied by the carrier and are not verified identity. They are frequently outdated, and for consumer lines often absent entirely.');
  }
  if (osm?.matched) {
    notes.push('The OpenStreetMap match is community-contributed and may be out of date or refer to a previous occupant of the premises. Treat it as a lead to confirm, not a fact.');
  }
  if (sec?.companies?.some((c) => !c.confirmed)) {
    notes.push('Some SEC matches are companies whose filings merely mention this number — an agent, a counterparty or an acquisition target. Only entries marked as filed are the company\'s own number.');
  }
  if (search) {
    notes.push('Search results are ranked by a search engine, not verified. Reverse-lookup spam sites dominate results for phone numbers and are filtered out of the name candidates, but read the sources before relying on any of them.');
  }
  if (!search) {
    notes.push('Search-engine footprint is off. Setting BRAVE_SEARCH_API_KEY enables it, and it is the single highest-yield technique for putting a name to a business number.');
  }
  if (!live && !osm?.matched && !sec?.matched) {
    notes.push('No name was found in any free source. These cover mapped businesses, US public companies and web presence — never private individuals, for whom no free authoritative source exists. Twilio credentials enable CNAM caller-ID lookup, which is billed per query.');
  }
  return notes;
}

function assess(phone, valid, type, carrier, live, osm, sec, plan, wiki) {
  const findings = [];

  if (!valid) {
    findings.push({
      level: 'danger',
      title: 'Not a valid number',
      detail: phone.isPossible()
        ? 'The digit count is plausible for this country, but the number does not fall inside any allocated range.'
        : 'The number has an implausible length for its country code.',
    });
    return findings;
  }

  findings.push({
    level: 'ok',
    title: `Valid ${(TYPE_LABELS[type] ?? 'number').toLowerCase()} for ${phone.country ?? 'this region'}`,
    detail: 'The number conforms to the published numbering plan.',
  });

  if (TYPE_NOTES[type]) {
    findings.push({ level: type === 'PREMIUM_RATE' ? 'warn' : 'info', title: TYPE_LABELS[type] ?? type, detail: TYPE_NOTES[type] });
  }
  if (carrier) {
    findings.push({ level: 'info', title: `Allocated to ${carrier}`, detail: 'Original range holder. Verify against portability data before relying on this.' });
  }

  if (plan) {
    findings.push({
      level: 'ok',
      title: `Rate centre: ${plan.rateCentre ?? 'unknown'}${plan.region ? `, ${plan.region}` : ''}`,
      detail: [
        plan.switchClli ? `Block homes on switch ${plan.switchClli}${plan.switchName ? ` (${plan.switchName})` : ''}${plan.switchType ? `, a ${plan.switchType}` : ''}` : null,
        plan.lata ? `LATA ${plan.lata}` : null,
        plan.company ? `allocated to ${plan.company}${plan.ocn ? ` (OCN ${plan.ocn})` : ''}` : null,
      ].filter(Boolean).join(' · ')
        + '. This is LERG data — the numbering plan\'s own record of where the block is homed, which is finer than any city-level estimate.',
    });

    if (plan.wholesaleCarrier) {
      findings.push({
        level: 'warn',
        title: `Block held by a wholesale carrier (${plan.company})`,
        detail: 'Carriers like this sell numbers programmatically with no address verification. The number can be minutes old, is not tied to a location, and is the usual source of spoofed and disposable caller IDs.',
      });
    } else if (plan.companyType === 'I') {
      findings.push({
        level: 'info',
        title: 'Incumbent carrier block',
        detail: `${plan.incumbentCarrier ?? plan.company} is the incumbent local exchange carrier for this rate centre, so the block predates the VoIP resale market.`,
      });
    }
  }

  if (wiki?.matched) {
    findings.push({
      level: 'ok',
      title: `Printed in ${wiki.articles.length} Wikipedia article(s)`,
      detail: wiki.articles.map((a) => a.title).join(', ')
        + '. A number published in an encyclopedia article belongs to something notable and named.',
    });
  }

  if (osm?.matched) {
    const first = osm.places[0];
    findings.push({
      level: 'ok',
      title: `Listed in OpenStreetMap as ${first.name}`,
      detail: [first.category, first.address].filter(Boolean).join(' · ')
        + (osm.places.length > 1 ? ` — and ${osm.places.length - 1} other mapped location(s) share this number.` : ''),
    });
  }

  if (sec?.matched) {
    const filed = sec.companies.find((c) => c.confirmed);
    if (filed) {
      findings.push({
        level: 'ok',
        title: `Filed with the SEC by ${filed.name}`,
        detail: [filed.industry, filed.location].filter(Boolean).join(' · ')
          + ` — this number is on ${filed.name}'s EDGAR profile, so the attribution is the company's own filing.`,
      });
    } else {
      findings.push({
        level: 'info',
        title: `Appears in SEC filings by ${sec.companies[0].name}`,
        detail: 'The number occurs in their filings but is not the number on their EDGAR profile, so it may belong to an agent or counterparty rather than the filer.',
      });
    }
  }

  if (live?.callerName) {
    findings.push({
      level: 'info',
      title: `Caller ID: ${live.callerName}`,
      detail: live.callerType === 'BUSINESS'
        ? 'CNAM business listing from the carrier database.'
        : 'CNAM subscriber listing. Carrier-maintained, and often stale or absent.',
    });
  }
  if (live?.currentCarrier && live.currentCarrier !== carrier) {
    findings.push({
      level: 'info',
      title: `Currently on ${live.currentCarrier}`,
      detail: `The range was allocated to ${carrier ?? 'another operator'}, so this number has been ported.`,
    });
  }
  return findings;
}

function exampleFor(country) {
  if (!country) return null;
  try {
    return getExampleNumber(country, examples)?.formatInternational() ?? null;
  } catch {
    return null;
  }
}

function explainParseError(code, value, region) {
  switch (code) {
    case 'NOT_A_NUMBER':
      return `"${value}" does not contain a recognisable phone number.`;
    case 'INVALID_COUNTRY':
      return region
        ? `"${region}" is not a country libphonenumber knows about.`
        : `"${value}" has no country code. Start it with "+" (for example +1 213 373 4253), or pick a region.`;
    case 'TOO_SHORT':
      return `"${value}" is too short to be a phone number.`;
    case 'TOO_LONG':
      return `"${value}" is too long to be a phone number.`;
    default:
      return `Could not parse "${value}": ${code}.`;
  }
}

/**
 * Search pivots. These are the places an investigator checks by hand — the tool
 * builds the query, the human runs it. Nothing is requested on their behalf.
 */
function pivots(e164) {
  const bare = e164.replace('+', '');
  const quoted = encodeURIComponent(`"${e164}"`);
  // One query covering every spelling at once, which is what actually finds a
  // number that a site wrote differently from the way you typed it.
  const anyForm = encodeURIComponent(`"${e164}" OR "${bare}"`);

  return [
    { label: 'Google', url: `https://www.google.com/search?q=${quoted}` },
    { label: 'Google (any format)', url: `https://www.google.com/search?q=${anyForm}` },
    { label: 'Bing', url: `https://www.bing.com/search?q=${quoted}` },
    { label: 'DuckDuckGo', url: `https://duckduckgo.com/?q=${quoted}` },
    { label: 'Yandex', url: `https://yandex.com/search/?text=${quoted}` },
    { label: 'Truecaller', url: `https://www.truecaller.com/search/global/${bare}` },
    { label: 'Sync.me', url: `https://sync.me/search/?number=${bare}` },
    { label: 'WhatsApp', url: `https://wa.me/${bare}` },
    { label: 'Telegram', url: `https://t.me/+${bare}` },
    { label: 'Signal', url: `https://signal.me/#p/${e164}` },
    { label: 'Facebook search', url: `https://www.facebook.com/search/top?q=${quoted}` },
    { label: 'LinkedIn via Google', url: `https://www.google.com/search?q=${encodeURIComponent(`site:linkedin.com "${e164}"`)}` },
    { label: 'Documents via Google', url: `https://www.google.com/search?q=${encodeURIComponent(`"${e164}" (filetype:pdf OR filetype:xlsx OR filetype:csv)`)}` },
    { label: 'Pastes via Google', url: `https://www.google.com/search?q=${encodeURIComponent(`"${e164}" (site:pastebin.com OR site:ghostbin.com OR site:gist.github.com)`)}` },
    { label: 'Have I Been Pwned', url: 'https://haveibeenpwned.com/' },
  ];
}
