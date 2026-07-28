/**
 * Live integration tests. These hit real upstream services, so they are opt-in:
 *
 *   GHOSTTRACE_LIVE=1 npm test
 *
 * They assert on structure and on the API contract, never on values that a
 * registry might legitimately change tomorrow.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { handleApiRequest } from '../src/router.js';

const live = process.env.GHOSTTRACE_LIVE === '1';

const loadData = async (path) => {
  try {
    return JSON.parse(await readFile(new URL(`../public/data/phone/${path}`, import.meta.url), 'utf8'));
  } catch {
    return null;
  }
};

async function call(path) {
  const request = new Request(new URL(path, 'http://localhost'));
  const response = await handleApiRequest(request, { env: process.env, loadData, basePath: '/api' });
  return { status: response.status, body: await response.json() };
}

describe('API contract', () => {
  test('health responds', async () => {
    const { status, body } = await call('/api/health');
    assert.equal(status, 200);
    assert.equal(body.status, 'ok');
  });

  test('index lists the endpoints', async () => {
    const { status, body } = await call('/api');
    assert.equal(status, 200);
    assert.ok(body.endpoints['GET /api/ip?q=<address>']);
  });

  test('unknown route 404s', async () => {
    assert.equal((await call('/api/nope')).status, 404);
  });

  test('missing parameter is a 400 with a usable message', async () => {
    const { status, body } = await call('/api/ip');
    assert.equal(status, 400);
    assert.match(body.detail, /Missing "q"/);
  });

  test('invalid input is a 400, not a 500', async () => {
    for (const path of ['/api/ip?q=999.1.1.1', '/api/domain?q=localhost', '/api/phone?q=abc']) {
      const { status, body } = await call(path);
      assert.equal(status, 400, `${path} should be 400`);
      assert.equal(body.error, 'Invalid input');
    }
  });

  test('private addresses short-circuit without upstream calls', async () => {
    const { status, body } = await call('/api/ip?q=192.168.1.1');
    assert.equal(status, 200);
    assert.equal(body.routable, false);
    assert.match(body.summary, /private/);
  });
});

describe('live lookups', { skip: live ? false : 'set GHOSTTRACE_LIVE=1 to run' }, () => {
  test('IP lookup returns geolocation, registry and exposure', async () => {
    const { status, body } = await call('/api/ip?q=8.8.8.8');
    assert.equal(status, 200);
    assert.equal(body.query.value, '8.8.8.8');
    assert.equal(body.geolocation.countryCode, 'US');
    assert.ok(body.geolocation.asn);
    assert.ok(body.registry.cidr);
    assert.equal(body.reverseDns, 'dns.google');
    assert.ok(Array.isArray(body.exposure.ports));
    assert.ok(body.assessment.length);
  });

  test('domain lookup returns registration, DNS and email posture', async () => {
    const { status, body } = await call('/api/domain?q=github.com');
    assert.equal(status, 200);
    assert.ok(body.registration.registrar);
    assert.ok(body.registration.ageDays > 0);
    assert.ok(body.dns.A.records.length);
    assert.ok(body.dns.NS.records.length);
    assert.ok(body.email.spf.record.startsWith('v=spf1'));
    assert.equal(body.email.dmarc.enforcing, true);
    // CAA must be decoded out of RFC 3597 generic form.
    assert.ok(body.dns.CAA.records.every((r) => !r.startsWith('\\#')));
  });

  test('at least one subdomain source answers', async () => {
    const { body } = await call('/api/domain?q=github.com');
    assert.ok(body.certificates.discoverySources.length >= 1);
    assert.ok(body.subdomains.length > 0);
  });

  test('a partly-failed source degrades rather than failing the report', async () => {
    const { status, body } = await call('/api/domain?q=github.com');
    assert.equal(status, 200);
    // Whatever happened upstream, every source is accounted for.
    for (const state of Object.values(body.sources)) {
      assert.equal(typeof state.ok, 'boolean');
      if (!state.ok) assert.ok(state.error);
    }
  });
});
