/**
 * Serves the GhostTrace Pages project at https://mattlavergne.com/OSINT.
 *
 * Cloudflare Pages custom domains are hostname-level only — a Pages project
 * cannot be attached to a *path*. This Worker bridges that: it takes the
 * /OSINT route on the zone, strips the prefix, and proxies to the Pages
 * deployment.
 *
 * The zone already has `trafficmap-proxy` on `mattlavergne.com/*`, which
 * currently answers /OSINT with the mattOS shell. Cloudflare resolves
 * overlapping routes by specificity, so `mattlavergne.com/OSINT*` wins over
 * that catch-all — the existing Worker needs no change and keeps serving
 * everything else.
 *
 * Deploy: see README, "Deploying to mattlavergne.com/OSINT".
 */

/** The Pages deployment to proxy to. Replace if your project name differs. */
const UPSTREAM = 'https://ghosttrace.pages.dev';

/** The path this app is mounted at. Must match the Worker route. */
const PREFIX = '/OSINT';

/**
 * Map an inbound public URL onto the upstream Pages URL.
 * Exported for tests; the Worker itself only needs `fetch`.
 */
export function rewrite(inbound) {
  const url = new URL(inbound);

  // Bare /OSINT must become /OSINT/ before anything else. The frontend derives
  // its API base from document.baseURI, and without the trailing slash the
  // browser resolves "api/ip" against the site root instead of the app.
  if (url.pathname === PREFIX) {
    return { redirect: `${url.origin}${PREFIX}/${url.search}` };
  }

  // The route pattern /OSINT* also matches things like /OSINTfoo. Those are not
  // ours. Refusing them is safer than re-fetching the request, which on a zone
  // fronted entirely by Workers risks looping back into this Worker.
  if (!url.pathname.startsWith(`${PREFIX}/`)) return { notFound: true };

  const upstream = new URL(UPSTREAM);
  upstream.pathname = url.pathname.slice(PREFIX.length);
  upstream.search = url.search;
  return { upstream: upstream.toString() };
}

export default {
  async fetch(request) {
    const target = rewrite(request.url);

    if (target.redirect) return Response.redirect(target.redirect, 301);
    if (target.notFound) return new Response('Not found', { status: 404 });

    const response = await fetch(new Request(target.upstream, request));

    // Pages may answer with its own redirects (trailing-slash normalisation).
    // Those carry upstream URLs, so rewrite them back into the public path.
    const location = response.headers.get('location');
    if (location?.startsWith(UPSTREAM)) {
      const fixed = new Headers(response.headers);
      fixed.set('location', PREFIX + location.slice(UPSTREAM.length));
      return new Response(response.body, { status: response.status, headers: fixed });
    }

    return response;
  },
};
