#!/usr/bin/env node
/**
 * Node server — the alternative to Cloudflare Pages.
 *
 * Serves the static frontend and mounts the same shared router at /api.
 * Intended to sit behind nginx at https://mattlavergne.com/OSINT (see
 * deploy/nginx.conf), but it runs standalone too.
 *
 *   PORT=8787 BASE_PATH=/OSINT node server/index.mjs
 */

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { handleApiRequest } from '../src/router.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const publicDir = join(root, 'public');

const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? '127.0.0.1';
/** Path prefix this app is mounted under, when proxied. */
const BASE_PATH = (process.env.BASE_PATH ?? '').replace(/\/$/, '');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
  '.woff2': 'font/woff2',
};

/** Reference-data loader backed by the local filesystem. */
async function loadData(path) {
  const file = safeJoin(join(publicDir, 'data', 'phone'), path);
  if (!file) return null;
  try {
    return JSON.parse(await readFile(file, 'utf8'));
  } catch {
    return null;
  }
}

/** Resolve `relative` under `base`, refusing anything that escapes it. */
function safeJoin(base, relative) {
  const resolved = normalize(join(base, relative));
  return resolved.startsWith(base) ? resolved : null;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);

  // Strip the mount prefix so routing is identical whether or not we're proxied.
  let pathname = url.pathname;
  if (BASE_PATH && pathname.startsWith(BASE_PATH)) {
    pathname = pathname.slice(BASE_PATH.length) || '/';
  }

  try {
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      const request = new Request(new URL(pathname + url.search, 'http://localhost'), {
        method: req.method,
        headers: req.headers,
        body: ['GET', 'HEAD'].includes(req.method) ? undefined : await readBody(req),
        duplex: 'half',
      });

      const response = await handleApiRequest(request, { env: process.env, loadData, basePath: '/api' });
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
      return;
    }

    await serveStatic(pathname, res);
  } catch (err) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Server error', detail: err.message }));
  }
});

async function serveStatic(pathname, res) {
  const relative = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
  const file = safeJoin(publicDir, relative);

  if (!file) {
    res.writeHead(403).end('Forbidden');
    return;
  }

  try {
    const info = await stat(file);
    if (info.isDirectory()) return serveStatic(join(pathname, 'index.html'), res);

    const body = await readFile(file);
    const type = MIME[extname(file)] ?? 'application/octet-stream';
    // Reference data is content-addressed by calling code and changes only on
    // rebuild, so it is safe to cache hard. The app shell is not.
    const cache = relative.startsWith('data/phone/')
      ? 'public, max-age=86400'
      : 'no-cache';
    res.writeHead(200, { 'content-type': type, 'cache-control': cache });
    res.end(body);
  } catch {
    // Single-page app: unknown paths fall through to the shell.
    const shell = await readFile(join(publicDir, 'index.html'));
    res.writeHead(404, { 'content-type': MIME['.html'] });
    res.end(shell);
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

server.listen(PORT, HOST, () => {
  console.log(`GhostTrace listening on http://${HOST}:${PORT}${BASE_PATH || ''}`);
});
