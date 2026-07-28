/**
 * Mount-prefix tests for the Worker entry point.
 *
 * The Worker is bound to `mattlavergne.com/OSINT*`, so every request arrives
 * with the prefix attached and must be stripped before dispatch. Getting this
 * subtly wrong — a lost trailing slash, a dropped query string, an API call
 * mistaken for an asset — breaks the app only in production. Cheap to pin here.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { resolvePath } from '../src/worker.js';

const at = (path) => `https://mattlavergne.com${path}`;

describe('Worker mount prefix', () => {
  test('redirects bare /osint to /osint/', () => {
    // Without the trailing slash the browser resolves the app's relative asset
    // and API URLs against the site root, and nothing loads.
    assert.deepEqual(resolvePath(at('/osint')), { redirect: at('/osint/') });
  });

  test('accepts either case, and keeps the spelling used', () => {
    // Cloudflare route paths are case-sensitive, so /osint* and /OSINT* are
    // different routes. Matching loosely means the app works whichever one is
    // attached; echoing the original spelling back means the redirect target
    // is still covered by that same route.
    assert.deepEqual(resolvePath(at('/OSINT')), { redirect: at('/OSINT/') });
    assert.deepEqual(resolvePath(at('/OSINT/api/health')), { path: '/api/health', isApi: true });
    assert.deepEqual(resolvePath(at('/osint/api/health')), { path: '/api/health', isApi: true });
    assert.deepEqual(resolvePath(at('/OsInt/assets/app.css')),
      { path: '/assets/app.css', isApi: false });
  });

  test('leaves the rest of the path byte-exact', () => {
    // Only the prefix is matched loosely; asset names are case-sensitive.
    assert.deepEqual(resolvePath(at('/osint/data/phone/geo/44.json')),
      { path: '/data/phone/geo/44.json', isApi: false });
    assert.deepEqual(resolvePath(at('/osint/Assets/App.CSS')),
      { path: '/Assets/App.CSS', isApi: false });
  });

  test('preserves the query string across that redirect', () => {
    assert.deepEqual(resolvePath(at('/osint?type=ip&q=8.8.8.8')), {
      redirect: at('/osint/?type=ip&q=8.8.8.8'),
    });
  });

  test('maps the app root', () => {
    assert.deepEqual(resolvePath(at('/osint/')), { path: '/', isApi: false });
  });

  test('maps static assets', () => {
    assert.deepEqual(resolvePath(at('/osint/assets/app.css')),
      { path: '/assets/app.css', isApi: false });
    assert.deepEqual(resolvePath(at('/osint/data/phone/geo/44.json')),
      { path: '/data/phone/geo/44.json', isApi: false });
  });

  test('recognises API calls under the prefix', () => {
    assert.deepEqual(resolvePath(at('/osint/api/domain?q=github.com')),
      { path: '/api/domain', isApi: true });
    assert.deepEqual(resolvePath(at('/osint/api/health')),
      { path: '/api/health', isApi: true });
  });

  test('does not treat a lookalike asset path as API', () => {
    assert.equal(resolvePath(at('/osint/assets/api.js')).isApi, false);
    assert.equal(resolvePath(at('/osint/apitest')).isApi, false);
  });

  test('works unprefixed, so a workers.dev deployment behaves the same', () => {
    // Same build, no /OSINT in the path — used for testing before the route
    // is attached to the domain.
    assert.deepEqual(resolvePath('https://osint.workers.dev/api/health'),
      { path: '/api/health', isApi: true });
    assert.deepEqual(resolvePath('https://osint.workers.dev/'),
      { path: '/', isApi: false });
  });

  test('leaves paths that merely start with the prefix string alone', () => {
    // /osintfoo is not inside the mount, so the prefix must not be stripped.
    assert.deepEqual(resolvePath(at('/osintfoo')), { path: '/osintfoo', isApi: false });
  });

  test('cannot be walked out of the mount', () => {
    // `new URL()` resolves dot segments before the prefix test runs, in both
    // plain and percent-encoded form, so traversal lands outside the mount and
    // is served as an ordinary (missing) asset rather than escaping anywhere.
    assert.deepEqual(resolvePath(at('/osint/../../etc/passwd')),
      { path: '/etc/passwd', isApi: false });
    assert.deepEqual(resolvePath(at('/osint/%2e%2e/admin')),
      { path: '/admin', isApi: false });
  });
});
