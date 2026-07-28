/**
 * Cloudflare Pages Function — catch-all for /api/*.
 *
 * Thin adapter: hands the incoming Request to the shared router and wires up
 * `loadData` so the phone module can read its reference shards straight out of
 * the Pages static asset bundle (no extra network hop, no origin round-trip).
 */

import { handleApiRequest } from '../../src/router.js';

export async function onRequest(context) {
  const { request, env } = context;

  const loadData = async (path) => {
    const assetUrl = new URL(`/data/phone/${path}`, request.url);
    const response = await env.ASSETS.fetch(new Request(assetUrl, { headers: { accept: 'application/json' } }));
    if (!response.ok) return null;
    return response.json();
  };

  return handleApiRequest(request, { env, loadData, basePath: '/api' });
}
