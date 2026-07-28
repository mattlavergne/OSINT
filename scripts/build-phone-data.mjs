#!/usr/bin/env node
/**
 * Convert libphonenumber-geo-carrier's BSON resources into static JSON assets.
 *
 * The upstream package reads its data with `fs` and `__dirname`, which makes it
 * Node-only — it cannot run on Cloudflare Workers. The data itself is just
 * prefix→string maps, so we emit it as static JSON that the API fetches on
 * demand. That keeps one code path for both runtimes, and keeps ~15 MB of
 * reference data out of the Worker bundle: a lookup for a UK number pulls a
 * 20 KB shard, and China's 4 MB shard is only ever touched by Chinese numbers.
 *
 * Output: public/data/phone/{geo,carrier}/<callingCode>.json
 *         public/data/phone/timezones.json
 *         public/data/phone/index.json
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deserialize } from 'bson';
import { getCountries, getCountryCallingCode } from 'libphonenumber-js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const source = join(root, 'node_modules', 'libphonenumber-geo-carrier', 'resources');
const target = join(root, 'public', 'data', 'phone');

const LOCALE = 'en';

function convertDirectory(kind) {
  const from = join(source, kind, LOCALE);
  const to = join(target, kind === 'geocodes' ? 'geo' : 'carrier');
  mkdirSync(to, { recursive: true });

  const callingCodes = [];
  let bytes = 0;

  for (const file of readdirSync(from)) {
    if (!file.endsWith('.bson')) continue;
    const callingCode = file.replace(/\.bson$/, '');
    const map = deserialize(readFileSync(join(from, file)));

    // BSON deserialization yields a prototype-bearing object; flatten to a
    // plain map so JSON.stringify emits only the prefix keys.
    const plain = {};
    for (const [prefix, value] of Object.entries(map)) {
      if (typeof value === 'string' && value) plain[prefix] = value;
    }

    const json = JSON.stringify(plain);
    writeFileSync(join(to, `${callingCode}.json`), json);
    callingCodes.push(callingCode);
    bytes += json.length;
  }

  console.log(`  ${kind}: ${callingCodes.length} calling codes, ${(bytes / 1e6).toFixed(1)} MB`);
  return callingCodes;
}

function convertTimezones() {
  const map = deserialize(readFileSync(join(source, 'timezones.bson')));
  const plain = {};
  for (const [prefix, value] of Object.entries(map)) {
    // Upstream packs multiple zones into one `&`-delimited string.
    if (typeof value === 'string' && value) plain[prefix] = value.split('&');
  }
  const json = JSON.stringify(plain);
  writeFileSync(join(target, 'timezones.json'), json);
  console.log(`  timezones: ${Object.keys(plain).length} prefixes, ${(json.length / 1e3).toFixed(0)} KB`);
}

console.log('Building phone reference data…');
rmSync(target, { recursive: true, force: true });
mkdirSync(target, { recursive: true });

const geo = convertDirectory('geocodes');
const carrier = convertDirectory('carrier');
convertTimezones();

// The region picker is driven off libphonenumber's own country list, so the UI
// can never offer a region the parser does not support.
const countries = getCountries().map((code) => ({
  code,
  callingCode: `+${getCountryCallingCode(code)}`,
}));

writeFileSync(
  join(target, 'index.json'),
  JSON.stringify({
    locale: LOCALE,
    generatedAt: new Date().toISOString(),
    geo: geo.sort((a, b) => a - b),
    carrier: carrier.sort((a, b) => a - b),
    countries,
  }),
);
console.log(`  index: ${countries.length} supported regions`);

console.log(`Done → ${target}`);
