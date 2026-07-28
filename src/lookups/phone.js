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
    timezones: Array.isArray(timezones) ? timezones : timezones ? [timezones] : [],
    localTime: localTimes(Array.isArray(timezones) ? timezones : []),
    caveats: caveats(valid, geo, carrier, type),
    example: exampleFor(phone.country),
    assessment: assess(phone, valid, type, carrier),
    pivots: pivots(phone.format('E.164')),
    sources: {
      libphonenumber: { ok: true },
      referenceData: { ok: geo !== undefined || carrier !== undefined },
    },
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

function caveats(valid, geo, carrier, type) {
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
  return notes;
}

function assess(phone, valid, type, carrier) {
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
