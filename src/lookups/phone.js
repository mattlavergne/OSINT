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
import { getJson } from '../lib/http.js';

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

export async function lookupPhone(input, region, loadData, env = {}) {
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
  const [places, live] = await Promise.all([
    valid ? openStreetMap(phone).catch((err) => ({ error: err.message })) : null,
    env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN
      ? twilioLookup(phone.format('E.164'), env).catch((err) => ({ error: err.message }))
      : null,
  ]);
  const osm = places && !places.error ? places : null;

  return {
    query: { type: 'phone', value, region: hintRegion ?? null },
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
    // Live, metered enrichment. Null unless Twilio credentials are configured.
    identity: live && !live.error ? live : null,
    identityError: live?.error ?? null,
    // Free, keyless business attribution from OpenStreetMap.
    places: osm?.places ?? [],
    timezones: Array.isArray(timezones) ? timezones : timezones ? [timezones] : [],
    localTime: localTimes(Array.isArray(timezones) ? timezones : []),
    caveats: caveats(valid, geo, carrier, type, live && !live.error ? live : null, osm),
    example: exampleFor(phone.country),
    assessment: assess(phone, valid, type, carrier, live && !live.error ? live : null, osm),
    pivots: pivots(phone.format('E.164')),
    sources: {
      libphonenumber: { ok: true },
      referenceData: { ok: geo !== undefined || carrier !== undefined },
      ...(places ? { openStreetMap: places.error ? { ok: false, error: places.error } : { ok: true } } : {}),
      ...(live ? { twilioLookup: live.error ? { ok: false, error: live.error } : { ok: true } } : {}),
    },
  };
}

/* --------------------------------------------------------- open-data lookup */

/** Overpass mirrors, tried in order. The main instance is often busy. */
const OVERPASS_MIRRORS = [
  'https://overpass-api.de/api/interpreter',
  'https://overpass.kumi.systems/api/interpreter',
];

/**
 * Reverse-lookup a phone number against OpenStreetMap.
 *
 * This is a genuinely free, keyless way to put a *name* to a number — the
 * catch is that it only covers businesses and public POIs that someone has
 * mapped, never individuals. When it hits, it is high quality: the operator
 * published the number themselves and the data is open (ODbL).
 *
 * OSM stores phone numbers as free text with wildly inconsistent punctuation,
 * and a planet-wide regex scan times out. So we generate the plausible
 * spellings from libphonenumber's own formatters and union exact matches,
 * which Overpass can serve off its value index in a couple of seconds.
 */
async function openStreetMap(phone) {
  const variants = phoneSpellings(phone);
  const clauses = variants
    .flatMap((v) => [`nwr["phone"="${v}"];`, `nwr["contact:phone"="${v}"];`])
    .join('');
  const query = `[out:json][timeout:20];(${clauses});out center tags;`;

  let lastError;
  for (const endpoint of OVERPASS_MIRRORS) {
    try {
      const body = await getJson(endpoint, {
        source: new URL(endpoint).hostname,
        method: 'POST',
        timeout: 14000,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: `data=${encodeURIComponent(query)}`,
      });

      const places = (body.elements ?? [])
        .filter((e) => e.tags?.name)
        .map((e) => ({
          name: e.tags.name,
          category: e.tags.amenity ?? e.tags.shop ?? e.tags.office ?? e.tags.tourism ?? e.tags.healthcare ?? null,
          operator: e.tags.operator ?? null,
          brand: e.tags.brand ?? null,
          address: [e.tags['addr:housenumber'], e.tags['addr:street'], e.tags['addr:city'], e.tags['addr:postcode']]
            .filter(Boolean).join(' ') || null,
          website: e.tags.website ?? e.tags['contact:website'] ?? null,
          phone: e.tags.phone ?? e.tags['contact:phone'] ?? null,
          osmUrl: `https://www.openstreetmap.org/${e.type}/${e.id}`,
        }))
        .slice(0, 10);

      return { matched: places.length > 0, places };
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError ?? new Error('No Overpass mirror responded');
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
  ])].filter(Boolean);
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

function caveats(valid, geo, carrier, type, live, osm) {
  const notes = [];
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
  if (!live && !osm?.matched) {
    notes.push('No name was found. OpenStreetMap only covers mapped businesses and public places, never individuals, and no free source exists for subscriber names. Configuring Twilio credentials enables CNAM caller-ID lookup, which is the only authoritative name source and is billed per query.');
  }
  return notes;
}

function assess(phone, valid, type, carrier, live, osm) {
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

  if (osm?.matched) {
    const first = osm.places[0];
    findings.push({
      level: 'ok',
      title: `Listed in OpenStreetMap as ${first.name}`,
      detail: [first.category, first.address].filter(Boolean).join(' · ')
        + (osm.places.length > 1 ? ` — and ${osm.places.length - 1} other mapped location(s) share this number.` : ''),
    });
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
  return [
    { label: 'Google', url: `https://www.google.com/search?q=${quoted}` },
    { label: 'Bing', url: `https://www.bing.com/search?q=${quoted}` },
    { label: 'DuckDuckGo', url: `https://duckduckgo.com/?q=${quoted}` },
    { label: 'Truecaller', url: `https://www.truecaller.com/search/global/${bare}` },
    { label: 'WhatsApp', url: `https://wa.me/${bare}` },
    { label: 'Telegram', url: `https://t.me/+${bare}` },
    { label: 'Have I Been Pwned', url: 'https://haveibeenpwned.com/' },
  ];
}
