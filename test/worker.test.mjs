/**
 * Path-rewriting tests for the /OSINT proxy Worker.
 *
 * The prefix maths is the whole job of that Worker, and getting it subtly wrong
 * (a lost trailing slash, a dropped query string) breaks the app in ways that
 * only show up in production. Cheap to pin down here.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { rewrite } from '../deploy/osint-proxy-worker.js';

const UPSTREAM = 'https://ghosttrace.pages.dev';

describe('OSINT proxy Worker', () => {
  test('redirects bare /OSINT to /OSINT/', () => {
    // Without the trailing slash the browser resolves the app's relative asset
    // and API URLs against the site root, and nothing loads.
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINT'), {
      redirect: 'https://mattlavergne.com/OSINT/',
    });
  });

  test('preserves the query string across that redirect', () => {
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINT?type=ip&q=8.8.8.8'), {
      redirect: 'https://mattlavergne.com/OSINT/?type=ip&q=8.8.8.8',
    });
  });

  test('maps the app root', () => {
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINT/'), { upstream: `${UPSTREAM}/` });
  });

  test('maps static assets', () => {
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINT/assets/app.css'),
      { upstream: `${UPSTREAM}/assets/app.css` });
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINT/data/phone/geo/44.json'),
      { upstream: `${UPSTREAM}/data/phone/geo/44.json` });
  });

  test('maps API calls with their query strings intact', () => {
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINT/api/domain?q=github.com'),
      { upstream: `${UPSTREAM}/api/domain?q=github.com` });
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINT/api/phone?q=%2B33612345678&region=FR'),
      { upstream: `${UPSTREAM}/api/phone?q=%2B33612345678&region=FR` });
  });

  test('refuses paths that only look like the prefix', () => {
    // The route pattern /OSINT* matches these too; they are not the app.
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINTfoo'), { notFound: true });
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINT-backup/secret'), { notFound: true });
  });

  test('cannot be walked out of the prefix', () => {
    // `new URL()` resolves the dot segments before the prefix test runs, so a
    // traversal attempt lands outside /OSINT/ and is refused rather than
    // rewritten. Either outcome is safe; this pins which one happens.
    // The URL parser also decodes %2e before normalising, so the encoded form
    // is neutralised identically.
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINT/../../etc/passwd'), { notFound: true });
    assert.deepEqual(rewrite('https://mattlavergne.com/OSINT/%2e%2e/%2e%2e/admin'), { notFound: true });
  });
});
