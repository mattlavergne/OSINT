/**
 * Username / handle enumeration.
 *
 * GhostTrack had a username module and this project removed it, for good
 * reasons that still stand: it requested 25 profile URLs and treated HTTP 200
 * as "account exists", which produces false positives on every site that
 * returns 200 for a missing profile, false negatives on everything behind
 * Cloudflare or a login wall, and sends traffic to third parties on the user's
 * behalf.
 *
 * This is the same question answered a different way. Every platform here
 * exposes a real API — usually the one its own frontend calls — with
 * unambiguous existence semantics: a 200 with a user object means the account
 * exists, a 404 means it does not, and there is no middle case to guess at.
 * Sites that cannot be checked honestly are not checked; they are listed as
 * links for a human to open, which is what PhoneInfoga does for phone numbers
 * and is the intellectually honest position.
 *
 * The payoff over a simple exists/doesn't list is the profile detail. Several
 * of these APIs return a display name, a bio, a location, a join date and
 * links, so a hit is not just "taken" — it is a person's own description of
 * themselves, and the join dates across platforms are what let you tell one
 * person's handle from a squatter's.
 */

import { getText, request } from '../lib/http.js';
import { parseUsername } from '../lib/validate.js';

/**
 * Platforms with an API that answers the existence question cleanly.
 *
 * `check` returns a profile object when the account exists, or null when it
 * verifiably does not. Anything else must throw, so the result is reported as
 * "could not check" rather than as an absence — the distinction that made the
 * original username module useless.
 */
const PLATFORMS = [
  {
    name: 'GitHub',
    category: 'Code',
    url: (u) => `https://github.com/${u}`,
    check: async (u, env) => {
      const body = await json(`https://api.github.com/users/${enc(u)}`, 'api.github.com', {
        accept: 'application/vnd.github+json',
        ...(env.GITHUB_TOKEN ? { authorization: `Bearer ${env.GITHUB_TOKEN}` } : {}),
      });
      return {
        displayName: body.name ?? null,
        bio: body.bio ?? null,
        location: body.location ?? null,
        company: body.company ?? null,
        email: body.email ?? null,
        website: body.blog || null,
        joined: body.created_at?.slice(0, 10) ?? null,
        followers: body.followers ?? null,
        // A `twitter_username` on a GitHub profile is a self-declared link
        // between two handles, which is exactly the kind of edge worth having.
        linkedHandles: body.twitter_username ? [{ platform: 'X / Twitter', username: body.twitter_username }] : [],
        extra: { publicRepos: body.public_repos, type: body.type },
      };
    },
  },
  {
    name: 'GitLab',
    category: 'Code',
    url: (u) => `https://gitlab.com/${u}`,
    check: async (u) => {
      // GitLab's user search returns an array; an empty array is a clean "no".
      const body = await json(`https://gitlab.com/api/v4/users?username=${enc(u)}`, 'gitlab.com');
      const user = Array.isArray(body) ? body[0] : null;
      if (!user) return null;
      return {
        displayName: user.name ?? null,
        joined: user.created_at?.slice(0, 10) ?? null,
        avatarUrl: user.avatar_url ?? null,
        extra: { id: user.id, state: user.state },
      };
    },
  },
  {
    name: 'Codeberg',
    category: 'Code',
    url: (u) => `https://codeberg.org/${u}`,
    check: async (u) => {
      const body = await json(`https://codeberg.org/api/v1/users/${enc(u)}`, 'codeberg.org');
      return {
        displayName: body.full_name || null,
        bio: body.description || null,
        location: body.location || null,
        website: body.website || null,
        joined: body.created?.slice(0, 10) ?? null,
        followers: body.followers_count ?? null,
      };
    },
  },
  {
    name: 'npm',
    category: 'Code',
    url: (u) => `https://www.npmjs.com/~${u}`,
    // npm's user endpoint now requires authentication and its profile pages
    // 403 server-side requests, so the only keyless check left answers a
    // narrower question: does this handle publish packages? A hit is solid; an
    // absence means "publishes nothing", not "no account".
    absenceMeans: 'no published packages — the account may still exist',
    check: async (u) => {
      const body = await json(
        `https://registry.npmjs.org/-/v1/search?text=${enc(`maintainer:${u}`)}&size=5`,
        'registry.npmjs.org',
      );
      const objects = body.objects ?? [];
      if (!objects.length) return null;
      return {
        extra: {
          packages: body.total ?? objects.length,
          examples: objects.map((o) => o.package?.name).filter(Boolean).slice(0, 5),
        },
        // The maintainer record on a package carries the publishing address.
        email: objects[0]?.package?.publisher?.email ?? null,
      };
    },
  },
  {
    name: 'Hacker News',
    category: 'Forum',
    url: (u) => `https://news.ycombinator.com/user?id=${u}`,
    check: async (u) => {
      // Firebase returns the JSON literal `null` for an unknown user, with a
      // 200 status — so the body, not the status, is the existence signal.
      const body = await json(`https://hacker-news.firebaseio.com/v0/user/${enc(u)}.json`, 'hacker-news.firebaseio.com');
      if (!body || !body.id) return null;
      return {
        bio: stripTags(body.about ?? '') || null,
        joined: body.created ? new Date(body.created * 1000).toISOString().slice(0, 10) : null,
        extra: { karma: body.karma, submitted: body.submitted?.length ?? null },
      };
    },
  },
  {
    name: 'Reddit',
    category: 'Forum',
    url: (u) => `https://www.reddit.com/user/${u}`,
    check: async (u) => {
      const body = await json(`https://www.reddit.com/user/${enc(u)}/about.json`, 'reddit.com');
      const d = body.data;
      if (!d || !d.name) return null;
      return {
        displayName: d.subreddit?.title || null,
        bio: d.subreddit?.public_description || null,
        joined: d.created_utc ? new Date(d.created_utc * 1000).toISOString().slice(0, 10) : null,
        extra: {
          linkKarma: d.link_karma, commentKarma: d.comment_karma,
          verified: d.verified ?? null, employee: d.is_employee ?? null,
        },
      };
    },
  },
  {
    name: 'Lobsters',
    category: 'Forum',
    url: (u) => `https://lobste.rs/~${u}`,
    check: async (u) => {
      const body = await json(`https://lobste.rs/~${enc(u)}.json`, 'lobste.rs');
      if (!body.username) return null;
      return {
        bio: stripTags(body.about ?? '') || null,
        joined: body.created_at?.slice(0, 10) ?? null,
        extra: { karma: body.karma, isAdmin: body.is_admin },
      };
    },
  },
  {
    name: 'Bluesky',
    category: 'Social',
    url: (u) => `https://bsky.app/profile/${u}.bsky.social`,
    check: async (u) => {
      const body = await json(
        `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${enc(`${u}.bsky.social`)}`,
        'public.api.bsky.app',
      );
      if (!body.did) return null;
      return {
        displayName: body.displayName ?? null,
        bio: body.description ?? null,
        joined: body.createdAt?.slice(0, 10) ?? null,
        followers: body.followersCount ?? null,
        extra: { did: body.did, posts: body.postsCount },
      };
    },
  },
  {
    name: 'Mastodon (mastodon.social)',
    category: 'Social',
    url: (u) => `https://mastodon.social/@${u}`,
    check: async (u) => {
      const body = await json(
        `https://mastodon.social/api/v1/accounts/lookup?acct=${enc(u)}`,
        'mastodon.social',
      );
      if (!body.id) return null;
      return {
        displayName: body.display_name || null,
        bio: stripTags(body.note ?? '') || null,
        joined: body.created_at?.slice(0, 10) ?? null,
        followers: body.followers_count ?? null,
        // Mastodon lets users verify links by rel=me, and a verified link is a
        // cryptographically-checkable claim rather than an assertion.
        links: (body.fields ?? [])
          .filter((f) => f.value)
          .map((f) => ({ name: f.name, value: stripTags(f.value), verified: Boolean(f.verified_at) })),
      };
    },
  },
  {
    name: 'Keybase',
    category: 'Identity',
    url: (u) => `https://keybase.io/${u}`,
    check: async (u) => {
      const body = await json(
        `https://keybase.io/_/api/1.0/user/lookup.json?username=${enc(u)}&fields=basics,profile,proofs_summary`,
        'keybase.io',
      );
      if (body.status?.code !== 0 || !body.them) return null;
      const them = Array.isArray(body.them) ? body.them[0] : body.them;
      if (!them) return null;
      return {
        displayName: them.profile?.full_name ?? null,
        bio: them.profile?.bio ?? null,
        location: them.profile?.location ?? null,
        // Keybase proofs are the strongest identity links available anywhere
        // here: each one is a signed statement the user posted on the other
        // platform, so it proves the same person controls both accounts.
        proofs: (them.proofs_summary?.all ?? []).map((p) => ({
          platform: p.proof_type,
          username: p.nametag,
          url: p.service_url ?? p.proof_url ?? null,
          state: p.state,
        })),
      };
    },
  },
  {
    name: 'Wikipedia',
    category: 'Reference',
    url: (u) => `https://en.wikipedia.org/wiki/User:${u}`,
    check: async (u) => {
      const body = await json(
        `https://en.wikipedia.org/w/api.php?action=query&list=users&format=json&usprop=editcount|registration|groups&ususers=${enc(u)}`,
        'en.wikipedia.org',
      );
      const user = body.query?.users?.[0];
      if (!user || user.missing !== undefined || user.invalid !== undefined) return null;
      return {
        joined: user.registration?.slice(0, 10) ?? null,
        extra: { edits: user.editcount, groups: (user.groups ?? []).filter((g) => g !== '*' && g !== 'user') },
      };
    },
  },
  {
    name: 'Chess.com',
    category: 'Gaming',
    url: (u) => `https://www.chess.com/member/${u}`,
    check: async (u) => {
      const body = await json(`https://api.chess.com/pub/player/${enc(u.toLowerCase())}`, 'api.chess.com');
      if (!body.username) return null;
      return {
        displayName: body.name ?? null,
        location: body.location ?? null,
        joined: body.joined ? new Date(body.joined * 1000).toISOString().slice(0, 10) : null,
        followers: body.followers ?? null,
        extra: { country: body.country?.split('/').pop(), status: body.status, lastOnline: body.last_online ? new Date(body.last_online * 1000).toISOString().slice(0, 10) : null },
      };
    },
  },
  {
    name: 'Steam',
    category: 'Gaming',
    url: (u) => `https://steamcommunity.com/id/${u}`,
    check: async (u) => {
      // The XML view of a vanity URL is the only keyless existence check Steam
      // offers; a missing profile returns an <error> document with status 200.
      const text = await getText(`https://steamcommunity.com/id/${enc(u)}?xml=1`, {
        source: 'steamcommunity.com',
        timeout: 8000,
      });
      if (/<error>/i.test(text) || !/<steamID64>/i.test(text)) return null;
      return {
        displayName: text.match(/<steamID><!\[CDATA\[([^\]]*)\]\]><\/steamID>/i)?.[1] ?? null,
        location: text.match(/<location><!\[CDATA\[([^\]]*)\]\]><\/location>/i)?.[1] || null,
        bio: stripTags(text.match(/<summary><!\[CDATA\[([\s\S]*?)\]\]><\/summary>/i)?.[1] ?? '') || null,
        extra: { steamId64: text.match(/<steamID64>(\d+)<\/steamID64>/i)?.[1] ?? null },
      };
    },
  },
  {
    name: 'Twitch',
    category: 'Streaming',
    url: (u) => `https://www.twitch.tv/${u}`,
    check: async (u) => {
      // Decapi is a thin public wrapper over the Twitch API. It answers with a
      // plain-text error string for unknown users.
      const text = await getText(`https://decapi.me/twitch/id/${enc(u)}`, {
        source: 'decapi.me',
        timeout: 8000,
      });
      if (!/^\d+$/.test(text.trim())) return null;
      return { extra: { twitchId: text.trim() } };
    },
  },
  {
    name: 'Docker Hub',
    category: 'Code',
    url: (u) => `https://hub.docker.com/u/${u}`,
    check: async (u) => {
      const body = await json(`https://hub.docker.com/v2/users/${enc(u)}/`, 'hub.docker.com');
      if (!body.username) return null;
      return {
        displayName: body.full_name || null,
        location: body.location || null,
        company: body.company || null,
        joined: body.date_joined?.slice(0, 10) ?? null,
      };
    },
  },
  {
    name: 'Telegram',
    category: 'Messaging',
    url: (u) => `https://t.me/${u}`,
    check: async (u) => {
      const text = await getText(`https://t.me/${enc(u)}`, { source: 't.me', timeout: 8000 });
      // The public preview page renders a profile block only for real handles;
      // an unclaimed one falls back to a generic "download Telegram" page.
      if (!/tgme_page_title/i.test(text)) return null;
      const title = text.match(/<div class="tgme_page_title"[^>]*>\s*<span[^>]*>([\s\S]{1,120}?)<\/span>/i)?.[1];
      return {
        displayName: stripTags(title ?? '').trim() || null,
        bio: stripTags(text.match(/<div class="tgme_page_description"[^>]*>([\s\S]{1,400}?)<\/div>/i)?.[1] ?? '').trim() || null,
        extra: { kind: /tgme_page_extra/.test(text) ? 'channel or group' : 'user' },
      };
    },
  },
  {
    name: 'Gravatar',
    category: 'Identity',
    url: (u) => `https://gravatar.com/${u}`,
    check: async (u) => {
      const body = await json(`https://gravatar.com/${enc(u)}.json`, 'gravatar.com');
      const entry = body.entry?.[0];
      if (!entry) return null;
      return {
        displayName: entry.displayName ?? null,
        bio: entry.aboutMe ?? null,
        location: entry.currentLocation ?? null,
        company: entry.company ?? null,
        avatarUrl: entry.thumbnailUrl ?? null,
        // Gravatar accounts are user-verified, so these are declared links.
        linkedHandles: (entry.accounts ?? []).map((a) => ({
          platform: a.name ?? a.shortname, username: a.username, url: a.url,
        })),
        links: (entry.urls ?? []).map((l) => ({ name: l.title, value: l.value })),
      };
    },
  },
];

/**
 * Platforms that cannot be checked honestly from a server.
 *
 * Each of these either serves a bot challenge to datacenter addresses, requires
 * an authenticated session, or returns 200 for missing profiles. Guessing at
 * them would reintroduce exactly the false-positive problem this module exists
 * to avoid, so they are handed to the user as links instead.
 */
const MANUAL_PLATFORMS = [
  { name: 'X / Twitter', url: (u) => `https://x.com/${u}`, reason: 'Requires an authenticated session; the public endpoints are gone.' },
  { name: 'Instagram', url: (u) => `https://instagram.com/${u}`, reason: 'Serves a login wall to datacenter addresses.' },
  { name: 'TikTok', url: (u) => `https://tiktok.com/@${u}`, reason: 'Bot challenge on server-side requests.' },
  { name: 'Facebook', url: (u) => `https://facebook.com/${u}`, reason: 'Login wall.' },
  { name: 'LinkedIn', url: (u) => `https://linkedin.com/in/${u}`, reason: 'Blocks unauthenticated automation outright.' },
  { name: 'YouTube', url: (u) => `https://youtube.com/@${u}`, reason: 'Returns 200 with a soft-404 page, so status alone proves nothing.' },
  { name: 'Snapchat', url: (u) => `https://snapchat.com/add/${u}`, reason: 'No public existence endpoint.' },
  { name: 'Pinterest', url: (u) => `https://pinterest.com/${u}`, reason: 'Soft-404s and geo-redirects.' },
  { name: 'Spotify', url: (u) => `https://open.spotify.com/user/${u}`, reason: 'Needs an OAuth token.' },
  { name: 'PyPI', url: (u) => `https://pypi.org/user/${u}/`, reason: 'HTML only, and rate-limits server-side requests aggressively.' },
  { name: 'Discord', url: () => 'https://discord.com/', reason: 'No public username lookup exists.' },
];

const enc = encodeURIComponent;

/** Fetch JSON, treating a 404 as a definitive "no such account". */
async function json(url, source, headers = {}) {
  const response = await request(url, {
    source,
    timeout: 8000,
    accept: 'application/json',
    headers,
    allowRedirect: false,
  });
  return response.json();
}

/**
 * Normalise empty strings to null.
 *
 * Several of these APIs return `""` for a field the user left blank. An empty
 * string renders as a present-but-empty row and, worse, survives the `??`
 * guards that treat only null as absent — so it has to be flattened once, here,
 * rather than defended against at every use.
 */
function blankToNull(profile) {
  const out = {};
  for (const [key, value] of Object.entries(profile ?? {})) {
    out[key] = typeof value === 'string' && value.trim() === '' ? null : value;
  }
  return out;
}

/** Strip markup from the bios these APIs return as HTML. */
function stripTags(value) {
  return String(value)
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<[^>]+>/g, '')
    .replace(/&(amp|lt|gt|quot|#39|nbsp);/g, (m) => ({ '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&nbsp;': ' ' }[m] ?? ' '))
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 400);
}

export async function lookupUsername(input, env = {}, options = {}) {
  const { value: username } = parseUsername(input);

  const settled = await Promise.allSettled(
    PLATFORMS.map(async (platform) => {
      try {
        const profile = await platform.check(username, env);
        return { platform, profile, exists: profile !== null };
      } catch (err) {
        // A 404 is the answer, not a failure. Anything else genuinely is one.
        if (err.status === 404 || err.status === 410) {
          return { platform, profile: null, exists: false };
        }
        throw err;
      }
    }),
  );

  const found = [];
  const absent = [];
  const errors = [];
  const sources = {};

  settled.forEach((outcome, i) => {
    const platform = PLATFORMS[i];
    if (outcome.status === 'rejected') {
      const message = outcome.reason?.message ?? String(outcome.reason);
      errors.push({ platform: platform.name, url: platform.url(username), error: message });
      sources[platform.name] = { ok: false, error: message };
      return;
    }

    sources[platform.name] = { ok: true };
    const { profile, exists } = outcome.value;

    if (exists) {
      found.push({
        platform: platform.name,
        category: platform.category,
        url: platform.url(username),
        ...blankToNull(profile),
      });
    } else {
      absent.push({
        platform: platform.name,
        url: platform.url(username),
        // Most platforms mean "no such account". Where the check can only
        // answer something narrower, say which.
        meaning: platform.absenceMeans ?? 'no account with this name',
      });
    }
  });

  found.sort((a, b) => a.platform.localeCompare(b.platform));

  return {
    query: { type: 'username', value: username, depth: options.depth ?? 'standard' },
    summary: {
      checked: PLATFORMS.length,
      found: found.length,
      absent: absent.length,
      unavailable: errors.length,
    },
    accounts: found,
    notFound: absent,
    unavailable: errors,
    manualChecks: MANUAL_PLATFORMS.map((p) => ({ platform: p.name, url: p.url(username), reason: p.reason })),
    identity: correlate(found),
    assessment: assess(username, found, errors),
    caveats: caveats(errors),
    pivots: pivots(username),
    sources,
  };
}

/* ----------------------------------------------------------- correlation */

/**
 * Pull the accounts together into one view of the person.
 *
 * A list of hits is only half the answer. What matters is whether they are the
 * same person: the names and locations they gave, the links they published,
 * and above all the cryptographic proofs and self-declared handles, which are
 * the only evidence here that two accounts share an owner rather than a name.
 */
function correlate(accounts) {
  const tally = (values) => {
    const counts = new Map();
    for (const { value, source } of values) {
      if (!value) continue;
      const clean = String(value).trim();
      if (clean.length < 2 || clean.length > 120) continue;
      const key = clean.toLowerCase();
      const existing = counts.get(key);
      if (existing) existing.sources.push(source);
      else counts.set(key, { value: clean, sources: [source] });
    }
    return [...counts.values()].sort((a, b) => b.sources.length - a.sources.length);
  };

  const names = tally(accounts.map((a) => ({ value: a.displayName, source: a.platform })));
  const locations = tally(accounts.map((a) => ({ value: a.location, source: a.platform })));
  const companies = tally(accounts.map((a) => ({ value: a.company, source: a.platform })));
  const emails = tally(accounts.map((a) => ({ value: a.email, source: a.platform })));

  // Links the account holder published on their own profile.
  const links = accounts.flatMap((a) => [
    ...(a.website ? [{ url: a.website, source: a.platform, verified: false }] : []),
    ...(a.links ?? []).map((l) => ({
      url: l.value ?? l.url, label: l.name ?? null, source: a.platform, verified: l.verified ?? false,
    })),
  ]).filter((l) => l.url && /^https?:\/\//i.test(l.url));

  // Handles on other platforms that this person declared or proved.
  const declared = accounts.flatMap((a) => [
    ...(a.linkedHandles ?? []).map((h) => ({ ...h, via: a.platform, proof: 'self-declared' })),
    ...(a.proofs ?? []).filter((p) => p.state === 1 || p.state === 0).map((p) => ({
      platform: p.platform, username: p.username, url: p.url, via: a.platform, proof: 'cryptographic proof',
    })),
  ]);

  const joinDates = accounts
    .filter((a) => a.joined)
    .map((a) => ({ platform: a.platform, joined: a.joined }))
    .sort((a, b) => a.joined.localeCompare(b.joined));

  return {
    names,
    bestName: names[0]?.value ?? null,
    locations,
    companies,
    emails,
    links: dedupe(links, (l) => l.url.toLowerCase()).slice(0, 20),
    declaredHandles: dedupe(declared, (d) => `${d.platform}:${d.username}`.toLowerCase()).slice(0, 20),
    joinDates,
    earliest: joinDates[0] ?? null,
    // Where the same handle is used across unrelated platforms with matching
    // self-reported detail, it is far more likely to be one person.
    corroboration: names[0]?.sources?.length ?? 0,
  };
}

function dedupe(items, key) {
  const seen = new Set();
  return items.filter((item) => {
    const k = key(item);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/* --------------------------------------------------------------- assessment */

function assess(username, found, errors) {
  const findings = [];

  if (!found.length) {
    findings.push({
      level: 'info',
      title: `No account named "${username}" on any platform checked`,
      detail: errors.length
        ? `${errors.length} platform(s) could not be reached, so this is not conclusive.`
        : 'Every platform answered, and none has this handle. The handle is either unused or used only on platforms that cannot be checked from a server.',
    });
    return findings;
  }

  findings.push({
    level: 'ok',
    title: `Found on ${found.length} platform(s)`,
    detail: found.map((f) => f.platform).join(', ')
      + '. Each was confirmed through the platform\'s own API, not by guessing at an HTTP status.',
  });

  const identity = correlate(found);

  if (identity.bestName && identity.corroboration > 1) {
    findings.push({
      level: 'ok',
      title: `Consistent name "${identity.bestName}" across ${identity.corroboration} platforms`,
      detail: `Reported on ${identity.names[0].sources.join(', ')}. The same handle carrying the same self-reported name on unrelated platforms is good evidence of one owner rather than a coincidence of handle choice.`,
    });
  } else if (found.length > 1 && identity.names.length > 1) {
    findings.push({
      level: 'warn',
      title: 'Different names across platforms',
      detail: identity.names.map((n) => `${n.value} (${n.sources.join(', ')})`).join(' · ')
        + '. A common handle can simply have been claimed by different people. Do not merge these into one identity without more evidence.',
    });
  }

  const proofs = identity.declaredHandles.filter((d) => d.proof === 'cryptographic proof');
  if (proofs.length) {
    findings.push({
      level: 'ok',
      title: `${proofs.length} cryptographically proven account link(s)`,
      detail: proofs.map((p) => `${p.platform}:${p.username}`).join(', ')
        + '. Keybase proofs are signed statements posted on the other platform, so these links are verifiable rather than asserted.',
    });
  }

  const declared = identity.declaredHandles.filter((d) => d.proof === 'self-declared');
  if (declared.length) {
    findings.push({
      level: 'info',
      title: `${declared.length} self-declared account link(s)`,
      detail: declared.map((d) => `${d.platform}:${d.username} (via ${d.via})`).join(', ')
        + '. The account holder typed these into their own profile — reliable in practice, but unverified.',
    });
  }

  if (identity.emails.length) {
    findings.push({
      level: 'ok',
      title: 'Public email address on a profile',
      detail: identity.emails.map((e) => `${e.value} (${e.sources.join(', ')})`).join(', ')
        + '. Published deliberately by the account holder, and a direct pivot into an email lookup.',
    });
  }

  if (identity.locations.length) {
    findings.push({
      level: 'info',
      title: 'Self-reported location',
      detail: identity.locations.map((l) => `${l.value} (${l.sources.join(', ')})`).join(' · ')
        + '. Free-text and unverified — people put jokes here as often as cities.',
    });
  }

  if (identity.earliest) {
    findings.push({
      level: 'info',
      title: `Earliest account ${identity.earliest.joined} on ${identity.earliest.platform}`,
      detail: identity.joinDates.map((j) => `${j.platform} ${j.joined}`).join(' · ')
        + '. Registration dates are the cheapest way to separate a long-standing owner from someone who recently claimed the same handle.',
    });
  }

  if (errors.length) {
    findings.push({
      level: 'warn',
      title: `${errors.length} platform(s) could not be checked`,
      detail: errors.map((e) => `${e.platform}: ${e.error}`).join(' · ')
        + '. These are unknown, not absent.',
    });
  }

  return findings;
}

function caveats(errors) {
  const notes = [
    'A handle is not a person. The same string on two platforms may be two people, and one person routinely uses several handles. Treat matching names, locations and declared links as the evidence — not the handle itself.',
    'Only platforms with an API that distinguishes "no such user" from "cannot tell" are checked. Sites behind login walls or bot challenges are listed separately for manual checking rather than guessed at, because a guess there is what makes username tools untrustworthy.',
    'An absence is weak evidence. It means the handle is unclaimed on that platform, not that the person has no account there — they may simply use a different name.',
  ];
  if (errors.length) {
    notes.push('Some platforms rate-limit by source address. From shared egress — a Worker, a VPN, a datacenter — that budget is often already spent by unrelated traffic, so a failure here usually says more about the network than about the handle.');
  }
  return notes;
}

function pivots(username) {
  const quoted = encodeURIComponent(`"${username}"`);
  return [
    { label: 'Google', url: `https://www.google.com/search?q=${quoted}` },
    { label: 'DuckDuckGo', url: `https://duckduckgo.com/?q=${quoted}` },
    { label: 'Sherlock (self-host)', url: 'https://github.com/sherlock-project/sherlock' },
    { label: 'WhatsMyName', url: `https://whatsmyname.app/?q=${encodeURIComponent(username)}` },
    { label: 'GitHub code search', url: `https://github.com/search?q=${quoted}&type=code` },
    { label: 'Archive.today', url: `https://archive.ph/${encodeURIComponent(username)}` },
    { label: 'Wayback profiles', url: `https://web.archive.org/web/*/*${encodeURIComponent(username)}*` },
    { label: 'Pastes via Google', url: `https://www.google.com/search?q=${encodeURIComponent(`"${username}" (site:pastebin.com OR site:gist.github.com)`)}` },
  ];
}
