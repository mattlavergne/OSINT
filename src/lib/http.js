/**
 * Minimal fetch helpers shared by every lookup module.
 *
 * Everything here is runtime-agnostic: it uses only `fetch`, `AbortSignal` and
 * `URL`, so the same code runs unchanged on Cloudflare Workers and on Node 20+.
 */

export const USER_AGENT =
  'GhostTrace/1.0 (+https://mattlavergne.com/OSINT; OSINT research tool)';

const DEFAULT_TIMEOUT_MS = 9000;

/** Raised when an upstream source fails, so callers can report which one broke. */
export class SourceError extends Error {
  constructor(source, message, status) {
    super(message);
    this.name = 'SourceError';
    this.source = source;
    this.status = status;
  }
}

/**
 * Fetch with a hard timeout and a descriptive error on non-2xx.
 *
 * @param {string} url
 * @param {{source: string, timeout?: number, headers?: Record<string,string>,
 *          accept?: string, method?: string, body?: string}} opts
 */
export async function request(url, opts) {
  const {
    source, timeout = DEFAULT_TIMEOUT_MS, headers = {}, accept,
    method = 'GET', body, cacheTtl,
  } = opts;

  let response;
  try {
    response = await fetch(url, {
      method,
      body,
      redirect: 'follow',
      signal: AbortSignal.timeout(timeout),
      // Cloudflare-specific; ignored by Node's fetch. Used for small static
      // reference data shared across every lookup, such as IANA bootstrap.
      ...(cacheTtl ? { cf: { cacheTtl, cacheEverything: true } } : {}),
      headers: {
        'user-agent': USER_AGENT,
        ...(accept ? { accept } : {}),
        ...headers,
      },
    });
  } catch (err) {
    const reason = err?.name === 'TimeoutError' ? `timed out after ${timeout}ms` : err.message;
    throw new SourceError(source, `${source} unreachable: ${reason}`);
  }

  if (!response.ok) {
    throw new SourceError(source, `${source} returned HTTP ${response.status}`, response.status);
  }
  return response;
}

/** Fetch and parse JSON. */
export async function getJson(url, opts) {
  const response = await request(url, { accept: 'application/json', ...opts });
  try {
    return await response.json();
  } catch {
    throw new SourceError(opts.source, `${opts.source} returned malformed JSON`);
  }
}

/** Fetch and return text. */
export async function getText(url, opts) {
  const response = await request(url, opts);
  return response.text();
}

/**
 * Run named async tasks concurrently and collect them into a single object,
 * so one dead upstream never takes down an entire report.
 *
 * Returns `{ data, sources }` where `sources` records ok/failed per task.
 *
 * @param {Record<string, () => Promise<any>>} tasks
 */
export async function gather(tasks) {
  const names = Object.keys(tasks);
  const settled = await Promise.allSettled(names.map((name) => tasks[name]()));

  const data = {};
  const sources = {};

  settled.forEach((outcome, i) => {
    const name = names[i];
    if (outcome.status === 'fulfilled') {
      data[name] = outcome.value;
      sources[name] = { ok: true };
    } else {
      data[name] = null;
      sources[name] = { ok: false, error: outcome.reason?.message ?? String(outcome.reason) };
    }
  });

  return { data, sources };
}
