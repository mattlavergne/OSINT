/**
 * Workers entry point — serves the whole app from a single Worker.
 *
 * Cloudflare's static-assets support means one Worker can serve `public/` and
 * run the API, so there is no separate Pages project and no proxy hop. This is
 * the deployment the dashboard steers you toward, and it is the default here.
 *
 * Mounting: the Worker is bound to `mattlavergne.com/OSINT*`, so requests
 * arrive with the `/OSINT` prefix still attached. It is stripped before
 * dispatch, which keeps routing identical to a root-mounted deployment. The
 * strip is conditional, so the same build also works unprefixed on a
 * *.workers.dev subdomain for testing.
 */

import { handleApiRequest } from './router.js';

/**
 * Path prefix this Worker is mounted under. Empty string means site root.
 *
 * Compared case-insensitively: the Cloudflare route pattern is case-sensitive,
 * so `/osint*` and `/OSINT*` are two different routes, and it is easy to mount
 * one and link the other. Matching loosely here means either spelling works
 * whichever route is attached. Only the prefix is treated this way — the rest
 * of the path stays byte-exact, since asset names are case-sensitive.
 */
const PREFIX = '/osint';

/**
 * Security headers applied to everything the Worker serves.
 *
 * `_headers` is a Pages convention and is not guaranteed under Workers static
 * assets, so the policy is set here where it is unambiguous. The CSP is strict
 * on purpose: the frontend has no inline scripts or styles, and every value it
 * renders comes from third-party registry and DNS text.
 */
const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=(), microphone=(), camera=()',
  // `img-src` names the Gravatar avatar hosts and nothing else. An email lookup
  // that finds a profile should be able to show the face attached to it — that
  // is often the identifying detail — and the alternative to this one narrow
  // exception is proxying images through the Worker, which would be a strictly
  // worse trade: more code, more egress, and the same third party still learns
  // the hash. Everything else stays same-origin.
  'content-security-policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; " +
    "img-src 'self' data: https://*.gravatar.com https://gravatar.com; " +
    "connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'self'",
};

/**
 * Resolve an inbound URL to a mount-relative path.
 *
 * Exported for tests: the prefix maths is the one piece here that fails
 * silently and only in production if it is wrong.
 *
 * @returns {{redirect: string} | {path: string, isApi: boolean}}
 */
export function resolvePath(inbound) {
  const url = new URL(inbound);
  const lower = url.pathname.toLowerCase();

  // Bare /osint must become /osint/. The frontend derives its API base from
  // document.baseURI; without the trailing slash the browser resolves
  // "api/ip" and "assets/app.css" against the site root, which on this zone
  // means the request falls through to whatever else serves the domain — you
  // get an unstyled page rather than an error.
  //
  // The redirect keeps the spelling the visitor used, so it works no matter
  // which case the route was attached with.
  if (PREFIX && lower === PREFIX) {
    return { redirect: `${url.origin}${url.pathname}/${url.search}` };
  }

  // Strip the mount prefix so downstream routing never has to know about it.
  // Conditional, so an unprefixed *.workers.dev deployment works identically.
  const path = PREFIX && lower.startsWith(`${PREFIX}/`)
    ? url.pathname.slice(PREFIX.length)
    : url.pathname;

  return { path, isApi: path === '/api' || path.startsWith('/api/') };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const resolved = resolvePath(request.url);

    if (resolved.redirect) return Response.redirect(resolved.redirect, 301);

    const { path } = resolved;

    if (resolved.isApi) {
      const apiUrl = new URL(url);
      apiUrl.pathname = path;
      const response = await handleApiRequest(new Request(apiUrl, request), {
        env,
        loadData: (file) => loadReferenceData(env, url, file),
        basePath: '/api',
      });
      return withHeaders(response);
    }

    return withHeaders(await serveAsset(env, url, path));
  },
};

/**
 * Read a static asset through the ASSETS binding.
 *
 * The binding is keyed on unprefixed paths, which is exactly what we have after
 * stripping. Unknown paths fall back to the app shell so deep links such as
 * /OSINT/?type=ip&q=8.8.8.8 survive a reload.
 */
async function serveAsset(env, url, path) {
  const assetUrl = new URL(path === '/' ? '/index.html' : path, url.origin);
  const response = await env.ASSETS.fetch(new Request(assetUrl, { method: 'GET' }));

  if (response.status !== 404) return response;

  // Fall back to the app shell only for navigation-style paths. A request for
  // a file — anything with an extension — must 404 honestly. Answering a
  // missing stylesheet with HTML and a 200 is how a misconfigured mount shows
  // up as "the CSS didn't load" instead of a clear error.
  if (/\.[a-z0-9]+$/i.test(path)) {
    return new Response(`Not found: ${path}`, {
      status: 404,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }

  return env.ASSETS.fetch(new Request(new URL('/index.html', url.origin)));
}

/** Phone reference data, fetched per calling code from the asset bundle. */
async function loadReferenceData(env, url, file) {
  const assetUrl = new URL(`/data/phone/${file}`, url.origin);
  const response = await env.ASSETS.fetch(
    new Request(assetUrl, { headers: { accept: 'application/json' } }),
  );
  return response.ok ? response.json() : null;
}

/** Attach security headers without disturbing the body or status. */
function withHeaders(response) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);

  // Reference data is content-addressed by calling code and only changes on a
  // rebuild, so it can be cached hard. Lookups never are.
  if (!headers.has('cache-control')) headers.set('cache-control', 'public, max-age=3600');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
