/**
 * Offline unit tests. No network, so these run anywhere and stay fast.
 * Live end-to-end coverage lives in integration.test.mjs.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  parseIp, parseDomain, parsePhoneInput, parseEmail, parseUsername, parseAsn,
  registrableDomain, ValidationError,
} from '../src/lib/validate.js';
import { expandIpv6, reverseName } from '../src/lib/dns.js';
import { parseVcard, entitiesByRole, eventDate, remarkText, geofeedUrl } from '../src/lib/rdap.js';
import { md5, murmur3, base64Lines, faviconHash } from '../src/lib/hash.js';
import {
  readPtr, mailProvider, dnsProvider, hostingOperator, fingerprint, isResolverRefusal,
} from '../src/lib/providers.js';
import { lookupPhone } from '../src/lookups/phone.js';

/** Keeps these tests genuinely offline, as the header above promises. */
const OFFLINE = { offline: true };

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
    const result = await lookupPhone('+1 213 373 4253', undefined, loadData, {}, OFFLINE);
    assert.equal(result.valid, true);
    assert.equal(result.country, 'US');
    assert.equal(result.formats.e164, '+12133734253');
    assert.equal(result.location, 'Los Angeles, CA');
    assert.deepEqual(result.timezones, ['America/Los_Angeles']);
  });

  test('resolves carrier where the range publishes one', async () => {
    const result = await lookupPhone('+33612345678', undefined, loadData, {}, OFFLINE);
    assert.equal(result.country, 'FR');
    assert.equal(result.numberType, 'MOBILE');
    assert.equal(result.carrier, 'SFR');
  });

  test('uses the region hint for national-format input', async () => {
    const result = await lookupPhone('0612345678', 'FR', loadData, {}, OFFLINE);
    assert.equal(result.valid, true);
    assert.equal(result.formats.e164, '+33612345678');
  });

  test('flags an invalid number rather than throwing', async () => {
    const result = await lookupPhone('+1 000 000 0000', undefined, loadData, {}, OFFLINE);
    assert.equal(result.valid, false);
    assert.equal(result.assessment[0].level, 'danger');
  });

  test('explains missing country context instead of leaking a parser code', async () => {
    await assert.rejects(() => lookupPhone('2133734253', undefined, loadData, {}, OFFLINE), (err) => {
      assert.ok(err instanceof ValidationError);
      assert.match(err.message, /country code|region/i);
      return true;
    });
  });

  test('works without reference data, just with less detail', async () => {
    const result = await lookupPhone('+12133734253', undefined, null, {}, OFFLINE);
    assert.equal(result.valid, true);
    assert.equal(result.location, null);
  });

  test('always states the portability and location caveats', async () => {
    const result = await lookupPhone('+33612345678', undefined, loadData, {}, OFFLINE);
    assert.ok(result.caveats.some((c) => /portability/i.test(c)));
  });
});

describe('email validation', () => {
  test('splits and normalises an address', () => {
    const email = parseEmail('  Support+Billing@Example.COM ');
    assert.equal(email.value, 'Support+Billing@example.com');
    assert.equal(email.local, 'Support+Billing');
    assert.equal(email.domain, 'example.com');
    assert.equal(email.tag, 'Billing');
    assert.equal(email.canonical, 'support@example.com');
  });

  test('canonicalises Gmail the way Gmail does', () => {
    // Dots are ignored and everything after "+" is dropped, so these are all
    // one mailbox — and Gravatar/breach lookups only find it under that form.
    for (const written of ['john.doe@gmail.com', 'j.o.h.n.d.o.e@gmail.com',
      'johndoe+shopping@googlemail.com', 'JohnDoe@Gmail.com']) {
      assert.equal(parseEmail(written).canonical, 'johndoe@gmail.com', written);
    }
    // Everywhere else, dots are significant and must be preserved.
    assert.equal(parseEmail('john.doe@fastmail.com').canonical, 'john.doe@fastmail.com');
  });

  test('accepts a mailto: prefix', () => {
    assert.equal(parseEmail('mailto:a@b.com').value, 'a@b.com');
  });

  test('rejects malformed addresses', () => {
    for (const bad of ['', 'nope', '@example.com', 'user@', 'user@localhost',
      '.user@example.com', 'user.@example.com', 'us..er@example.com',
      'user name@example.com', `${'a'.repeat(65)}@example.com`]) {
      assert.throws(() => parseEmail(bad), ValidationError, `should reject ${JSON.stringify(bad)}`);
    }
  });
});

describe('username validation', () => {
  test('accepts the forms people paste', () => {
    assert.equal(parseUsername('torvalds').value, 'torvalds');
    assert.equal(parseUsername('@torvalds').value, 'torvalds');
    assert.equal(parseUsername('https://github.com/torvalds').value, 'torvalds');
    assert.equal(parseUsername('https://mastodon.social/@torvalds').value, 'torvalds');
    assert.equal(parseUsername('torvalds@mastodon.social').value, 'torvalds');
  });

  test('rejects anything that is not a handle', () => {
    for (const bad of ['', 'a', 'a'.repeat(40), 'has space', 'semi;colon', '-leading']) {
      assert.throws(() => parseUsername(bad), ValidationError, `should reject ${JSON.stringify(bad)}`);
    }
  });
});

describe('ASN validation', () => {
  test('accepts every spelling of an AS number', () => {
    for (const written of ['AS15169', 'as15169', '15169']) {
      assert.deepEqual(parseAsn(written), { value: 15169, label: 'AS15169', reserved: false });
    }
  });

  test('flags private and documentation ranges rather than looking them up', () => {
    assert.equal(parseAsn('64512').reserved, true);
    assert.equal(parseAsn('4200000001').reserved, true);
    assert.equal(parseAsn('0').reserved, true);
  });

  test('rejects non-numbers and out-of-range values', () => {
    for (const bad of ['', 'ASN', 'AS-SET', '4294967296', '-1']) {
      assert.throws(() => parseAsn(bad), ValidationError, `should reject ${JSON.stringify(bad)}`);
    }
  });
});

describe('hashes', () => {
  test('MD5 matches the published vectors', () => {
    assert.equal(md5(''), 'd41d8cd98f00b204e9800998ecf8427e');
    assert.equal(md5('abc'), '900150983cd24fb0d6963f7d28e17f72');
    assert.equal(md5('The quick brown fox jumps over the lazy dog'),
      '9e107d9d372bb6826bd81d3542a419d6');
    // Longer than one 64-byte block, which exercises the padding path.
    assert.equal(md5('a'.repeat(1000)), 'cabe45dcc9ae5b66ba86600cca6b8ba8');
  });

  test('MurmurHash3 matches the reference implementation', () => {
    assert.equal(murmur3(''), 0);
    assert.equal(murmur3('hello'), 613153351);
    assert.equal(murmur3('The quick brown fox jumps over the lazy dog'), 776992547);
    // A non-zero seed must change the result.
    assert.notEqual(murmur3('hello', 1), murmur3('hello', 0));
  });

  test('base64 is wrapped the way Python encodebytes wraps it', () => {
    // Shodan hashes the output of base64.encodebytes, which breaks lines at 76
    // characters and ends with a newline. Hashing unwrapped base64 produces a
    // valid hash of the wrong string, and every search built on it finds nothing.
    const encoded = base64Lines(new Uint8Array(120).fill(65));
    assert.ok(encoded.endsWith('\n'));
    for (const line of encoded.trimEnd().split('\n')) {
      assert.ok(line.length <= 76, `line too long: ${line.length}`);
    }
    assert.equal(encoded.replace(/\n/g, ''), Buffer.from(new Uint8Array(120).fill(65)).toString('base64'));
  });

  test('favicon hash is stable and signed', () => {
    const bytes = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const hash = faviconHash(bytes);
    assert.equal(typeof hash, 'number');
    assert.equal(hash, faviconHash(bytes));
    assert.ok(hash >= -2147483648 && hash <= 2147483647);
  });
});

describe('provider fingerprints', () => {
  test('names mail and DNS operators from their hostnames', () => {
    assert.equal(mailProvider('aspmx.l.google.com'), 'Google Workspace');
    assert.equal(mailProvider('example-com.mail.protection.outlook.com'), 'Microsoft 365');
    assert.equal(mailProvider('route1.mx.cloudflare.net'), 'Cloudflare Email Routing');
    assert.equal(mailProvider('mail.self-hosted.example'), null);

    assert.equal(dnsProvider('ns-1283.awsdns-32.org'), 'Amazon Route 53');
    assert.equal(dnsProvider('kate.ns.cloudflare.com'), 'Cloudflare');
    assert.equal(hostingOperator('Hetzner Online GmbH'), 'Hetzner');
  });

  test('reads platform and region out of a PTR record', () => {
    const ec2 = readPtr('ec2-3-8-1-2.eu-west-2.compute.amazonaws.com');
    assert.equal(ec2.platform, 'Amazon EC2');
    assert.equal(ec2.region, 'eu-west-2');

    // us-east-1 is the one region that does not name itself in the PTR.
    assert.equal(readPtr('ec2-1-2-3-4.compute-1.amazonaws.com').region, 'us-east-1');

    assert.equal(readPtr('dsl-1-2-3-4.example.net').kind, 'residential access');
    assert.equal(readPtr(null), null);
    assert.equal(readPtr('host.nothing-special.example'), null);
  });

  test('distinguishes a blocklist hit from a refused query', () => {
    // Zones that refuse public resolvers answer in 127.255.255.x. Reading that
    // as a listing would flag every address on the internet.
    assert.equal(isResolverRefusal('127.255.255.254'), true);
    assert.equal(isResolverRefusal('127.0.0.1'), true);
    assert.equal(isResolverRefusal('127.0.0.2'), false);
    assert.equal(isResolverRefusal('127.0.0.10'), false);
  });

  test('fingerprints technologies from headers, cookies and page source', () => {
    const found = fingerprint({
      headers: new Headers({ server: 'nginx/1.24', 'x-powered-by': 'Express', 'cf-ray': 'abc' }),
      html: '<script src="/_next/static/x.js"></script><div id="__NEXT_DATA__"></div>',
      cookies: 'PHPSESSID=abc; laravel_session=def',
    });
    const names = found.map((t) => t.name);
    for (const expected of ['nginx', 'Express', 'Cloudflare', 'Next.js', 'Laravel']) {
      assert.ok(names.includes(expected), `expected to detect ${expected}, got ${names.join(', ')}`);
    }
    // Every hit records what it was detected from, so a false positive is debuggable.
    assert.ok(found.every((t) => t.evidence));
  });
});

describe('RDAP extras', () => {
  test('flattens remarks to plain lines', () => {
    const lines = remarkText([
      { description: ['Line one', 'Line two'] },
      { description: ['x'] }, // too short to be useful
    ]);
    assert.deepEqual(lines, ['Line one', 'Line two']);
  });

  test('finds a geofeed in a typed link or in a remark', () => {
    assert.equal(
      geofeedUrl({ links: [{ rel: 'geofeed', href: 'https://example.com/geofeed.csv' }] }),
      'https://example.com/geofeed.csv',
    );
    // RFC 9092 also allows a bare "geofeed:" line inside a remark, and most of
    // the geofeeds in the wild are published that way.
    assert.equal(
      geofeedUrl({ remarks: [{ description: ['geofeed: https://example.net/geo.csv.'] }] }),
      'https://example.net/geo.csv',
    );
    assert.equal(geofeedUrl({}), null);
  });
});
