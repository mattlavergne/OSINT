/**
 * Offline unit tests. No network, so these run anywhere and stay fast.
 * Live end-to-end coverage lives in integration.test.mjs.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { parseIp, parseDomain, parsePhoneInput, registrableDomain, ValidationError } from '../src/lib/validate.js';
import { expandIpv6, reverseName } from '../src/lib/dns.js';
import { parseVcard, entitiesByRole, eventDate } from '../src/lib/rdap.js';
import { lookupPhone } from '../src/lookups/phone.js';

const loadData = async (path) => {
  try {
    return JSON.parse(await readFile(new URL(`../public/data/phone/${path}`, import.meta.url), 'utf8'));
  } catch {
    return null;
  }
};

describe('IP validation', () => {
  test('accepts and classifies IPv4', () => {
    assert.deepEqual(parseIp('8.8.8.8'), { value: '8.8.8.8', version: 4, scope: 'public' });
    assert.equal(parseIp('192.168.1.1').scope, 'private');
    assert.equal(parseIp('10.0.0.1').scope, 'private');
    assert.equal(parseIp('172.16.0.1').scope, 'private');
    assert.equal(parseIp('172.32.0.1').scope, 'public');
    assert.equal(parseIp('127.0.0.1').scope, 'loopback');
    assert.equal(parseIp('169.254.1.1').scope, 'link-local');
    assert.equal(parseIp('100.64.0.1').scope, 'cgnat');
  });

  test('accepts IPv6 in every compression form', () => {
    assert.equal(parseIp('2606:4700:4700::1111').version, 6);
    assert.equal(parseIp('2001:0db8:0000:0000:0000:ff00:0042:8329').version, 6);
    assert.equal(parseIp('2001:db8::').version, 6);
    assert.equal(parseIp('::ffff:192.0.2.1').version, 6);
    assert.equal(parseIp('::').scope, 'public');
    assert.equal(parseIp('::1').scope, 'loopback');
    assert.equal(parseIp('fe80::1').scope, 'link-local');
    assert.equal(parseIp('fd00::1').scope, 'private');
  });

  test('rejects malformed IPv6', () => {
    for (const bad of [
      '2001:db8::1::2',        // two compressions
      '2001:db8:::1',          // triple colon
      '12345::1',              // over-long group
      '2001:0db8:0000:0000:0000:ff00:0042:8329:extra', // nine groups
      '2001:db8:0:0:0:ff00:42', // seven groups, uncompressed
      '::ffff:999.0.2.1',      // bad dotted quad
      'gggg::1',
    ]) {
      assert.throws(() => parseIp(bad), ValidationError, `should reject ${bad}`);
    }
  });

  test('rejects malformed input', () => {
    for (const bad of ['999.1.1.1', '1.2.3', 'not-an-ip', '', '1.2.3.4.5']) {
      assert.throws(() => parseIp(bad), ValidationError, `should reject ${bad}`);
    }
  });

  test('rejects zero-padded octets, which some resolvers read as octal', () => {
    assert.throws(() => parseIp('010.0.0.1'), ValidationError);
  });
});

describe('domain validation', () => {
  test('normalizes URLs down to a hostname', () => {
    assert.equal(parseDomain('https://User@Example.COM:8443/path?q=1#frag').value, 'example.com');
    assert.equal(parseDomain('example.com.').value, 'example.com');
    assert.equal(parseDomain('  sub.Example.co.uk  ').value, 'sub.example.co.uk');
  });

  test('allows underscore service labels', () => {
    assert.equal(parseDomain('_dmarc.example.com').value, '_dmarc.example.com');
  });

  test('rejects malformed input', () => {
    for (const bad of ['localhost', '', 'example', 'exa mple.com', 'a..b.com', '-bad.example.com']) {
      assert.throws(() => parseDomain(bad), ValidationError, `should reject ${bad}`);
    }
  });

  test('finds the registrable domain past multi-part suffixes', () => {
    assert.equal(registrableDomain(['a', 'b', 'example', 'com']), 'example.com');
    assert.equal(registrableDomain(['www', 'example', 'co', 'uk']), 'example.co.uk');
    assert.equal(registrableDomain(['example', 'com']), 'example.com');
  });
});

describe('phone input validation', () => {
  test('accepts common punctuation', () => {
    assert.equal(parsePhoneInput('+1 (213) 373-4253').value, '+1 (213) 373-4253');
    assert.equal(parsePhoneInput('0612345678', 'fr').region, 'FR');
  });

  test('rejects junk and bad regions', () => {
    assert.throws(() => parsePhoneInput('abc'), ValidationError);
    assert.throws(() => parsePhoneInput(''), ValidationError);
    assert.throws(() => parsePhoneInput('+1234567890', 'FRA'), ValidationError);
    assert.throws(() => parsePhoneInput('<script>1</script>'), ValidationError);
  });
});

describe('DNS helpers', () => {
  test('expands compressed IPv6', () => {
    assert.equal(expandIpv6('::1'), '0000:0000:0000:0000:0000:0000:0000:0001');
    assert.equal(expandIpv6('2606:4700::1111'), '2606:4700:0000:0000:0000:0000:0000:1111');
  });

  test('builds reverse lookup names', () => {
    assert.equal(reverseName('8.8.4.4', 4), '4.4.8.8.in-addr.arpa');
    assert.ok(reverseName('::1', 6).endsWith('.ip6.arpa'));
  });
});

describe('RDAP parsing', () => {
  test('flattens a jCard', () => {
    const card = parseVcard(['vcard', [
      ['version', {}, 'text', '4.0'],
      ['fn', {}, 'text', 'Example Registrar'],
      ['org', {}, 'text', 'Example Inc'],
      ['email', {}, 'text', 'abuse@example.com'],
      ['tel', {}, 'uri', 'tel:+1.5555550100'],
    ]]);
    assert.equal(card.name, 'Example Registrar');
    assert.equal(card.email, 'abuse@example.com');
    assert.equal(card.phone, '+1.5555550100');
  });

  test('finds nested abuse contacts', () => {
    const roles = entitiesByRole([{
      handle: 'REG',
      roles: ['registrar'],
      vcardArray: ['vcard', [['fn', {}, 'text', 'Registrar Co']]],
      entities: [{
        roles: ['abuse'],
        vcardArray: ['vcard', [['email', {}, 'text', 'abuse@registrar.example']]],
      }],
    }]);
    assert.equal(roles.registrar.name, 'Registrar Co');
    assert.equal(roles.abuse.email, 'abuse@registrar.example');
  });

  test('reads event dates', () => {
    const events = [{ eventAction: 'registration', eventDate: '2007-10-09T18:20:50Z' }];
    assert.equal(eventDate(events, 'registration'), '2007-10-09T18:20:50Z');
    assert.equal(eventDate(events, 'expiration'), null);
  });
});

describe('phone lookup', () => {
  test('parses a US number and resolves its allocation area', async () => {
    const result = await lookupPhone('+1 213 373 4253', undefined, loadData);
    assert.equal(result.valid, true);
    assert.equal(result.country, 'US');
    assert.equal(result.formats.e164, '+12133734253');
    assert.equal(result.location, 'Los Angeles, CA');
    assert.deepEqual(result.timezones, ['America/Los_Angeles']);
  });

  test('resolves carrier where the range publishes one', async () => {
    const result = await lookupPhone('+33612345678', undefined, loadData);
    assert.equal(result.country, 'FR');
    assert.equal(result.numberType, 'MOBILE');
    assert.equal(result.carrier, 'SFR');
  });

  test('uses the region hint for national-format input', async () => {
    const result = await lookupPhone('0612345678', 'FR', loadData);
    assert.equal(result.valid, true);
    assert.equal(result.formats.e164, '+33612345678');
  });

  test('flags an invalid number rather than throwing', async () => {
    const result = await lookupPhone('+1 000 000 0000', undefined, loadData);
    assert.equal(result.valid, false);
    assert.equal(result.assessment[0].level, 'danger');
  });

  test('explains missing country context instead of leaking a parser code', async () => {
    await assert.rejects(() => lookupPhone('2133734253', undefined, loadData), (err) => {
      assert.ok(err instanceof ValidationError);
      assert.match(err.message, /country code|region/i);
      return true;
    });
  });

  test('works without reference data, just with less detail', async () => {
    const result = await lookupPhone('+12133734253', undefined, null);
    assert.equal(result.valid, true);
    assert.equal(result.location, null);
  });

  test('always states the portability and location caveats', async () => {
    const result = await lookupPhone('+33612345678', undefined, loadData);
    assert.ok(result.caveats.some((c) => /portability/i.test(c)));
  });
});
