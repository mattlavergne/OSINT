/**
 * Email address intelligence.
 *
 * The honest framing first: there is no free, lawful source that turns an
 * arbitrary email address into a person's name. What there *is* — and what
 * almost nothing surfaces together — is a set of public records keyed on the
 * address or its hash, each of which narrows the question:
 *
 *   - Gravatar publishes a profile for any address whose owner made one, keyed
 *     by hash, and that profile often carries a real name, a location and a
 *     list of the owner's other accounts. It is the single highest-yield free
 *     source for an individual, and it is queried by digest, so the address
 *     itself is never sent anywhere.
 *   - GitHub indexes the commit addresses of every public contributor, so an
 *     address that has ever authored a public commit resolves to an account.
 *   - The domain half answers a different and often more useful question: does
 *     this address belong to an organisation, a consumer mailbox, a throwaway,
 *     or a forwarding alias — and is the mailbox even deliverable.
 *
 * Nothing here probes the mailbox. SMTP verification is not possible from a
 * Worker, is unreliable against modern mail servers, and generates traffic to a
 * third party on the user's behalf, so the report says what DNS supports and
 * stops there.
 */

import { getJson, gather } from '../lib/http.js';
import { resolve, resolveBatch } from '../lib/dns.js';
import { parseEmail } from '../lib/validate.js';
import { md5, sha256 } from '../lib/hash.js';
import {
  FREE_MAIL_DOMAINS, DISPOSABLE_MAIL_DOMAINS, ALIAS_MAIL_DOMAINS,
  ROLE_LOCAL_PARTS, MAIL_TYPOS, DKIM_SELECTORS, mailProvider,
} from '../lib/providers.js';
import * as rdap from '../lib/rdap.js';

export async function lookupEmail(input, env = {}, options = {}) {
  const email = parseEmail(input);
  const deep = options.depth === 'deep';

  // Gravatar is keyed by the hash of the lower-cased address. Both digests are
  // computed: SHA-256 is current, MD5 is what older profile links still use.
  const [addressMd5, addressSha256] = await Promise.all([
    Promise.resolve(md5(email.canonical)),
    sha256(email.canonical),
  ]);

  const { data, sources } = await gather({
    gravatar: () => gravatarProfile(addressSha256, addressMd5),
    mail: () => mailPosture(email.domain),
    registration: () => domainAge(email),
    github: () => githubByEmail(email, env),
    ...(deep ? { dkim: () => sendingPlatforms(email.domain) } : {}),
    ...(env.HIBP_API_KEY ? { breaches: () => haveIBeenPwned(email.value, env.HIBP_API_KEY) } : {}),
    ...(env.VIRUSTOTAL_API_KEY
      ? { reputation: () => virusTotalDomain(email.domain, env.VIRUSTOTAL_API_KEY) }
      : {}),
  });

  const classification = classify(email, data);

  return {
    query: { type: 'email', value: email.value, depth: options.depth ?? 'standard' },
    address: {
      local: email.local,
      domain: email.domain,
      // The canonical form is what Gravatar and most breach corpora key on.
      canonical: email.canonical,
      // A "+tag" usually records where the address was handed out.
      subAddressTag: email.tag,
      md5: addressMd5,
      sha256: addressSha256,
    },
    classification,
    gravatar: data.gravatar ?? null,
    accounts: data.github ?? null,
    mail: data.mail,
    sendingPlatforms: data.dkim ?? null,
    domainRegistration: data.registration ?? null,
    breaches: data.breaches ?? null,
    reputation: data.reputation ?? null,
    // Candidate usernames derived from the local part, for a username lookup.
    usernameCandidates: usernameCandidates(email),
    identity: identity(data),
    assessment: assess(email, data, classification),
    caveats: caveats(data, env),
    pivots: pivots(email, addressMd5, addressSha256),
    sources,
  };
}

/* ------------------------------------------------------------------ sources */

/**
 * Gravatar profile.
 *
 * Gravatar is attached to a WordPress account and to every site using it for
 * avatars, and the profile is public JSON keyed by the hash of the address.
 * Where the owner filled it in, it carries a display name, a location, a bio
 * and — most valuable — a verified list of their other accounts, which is a
 * ready-made pivot set that no amount of guessing would produce.
 *
 * A 404 means no profile exists, which is a clean answer rather than an error.
 */
async function gravatarProfile(sha, md) {
  for (const hash of [sha, md]) {
    try {
      const body = await getJson(`https://gravatar.com/${hash}.json`, {
        source: 'gravatar.com',
        timeout: 8000,
        headers: { accept: 'application/json' },
      });

      const entry = body.entry?.[0];
      if (!entry) continue;

      return {
        exists: true,
        hash,
        username: entry.preferredUsername ?? null,
        displayName: entry.displayName ?? null,
        name: [entry.name?.givenName, entry.name?.familyName].filter(Boolean).join(' ') || entry.name?.formatted || null,
        location: entry.currentLocation ?? null,
        aboutMe: entry.aboutMe ?? null,
        jobTitle: entry.job_title ?? null,
        company: entry.company ?? null,
        pronouns: entry.pronouns ?? null,
        profileUrl: entry.profileUrl ?? `https://gravatar.com/${hash}`,
        avatarUrl: entry.thumbnailUrl ?? null,
        // The owner proved control of these; they are not guesses.
        verifiedAccounts: (entry.accounts ?? []).map((a) => ({
          platform: a.name ?? a.shortname ?? null,
          username: a.username ?? null,
          url: a.url ?? null,
          verified: a.verified === true || a.verified === 'true',
        })),
        urls: (entry.urls ?? []).map((u) => ({ title: u.title ?? null, url: u.value ?? null })),
        emails: (entry.emails ?? []).map((e) => e.value).filter(Boolean),
      };
    } catch (err) {
      if (err.status === 404) continue;
      throw err;
    }
  }

  return { exists: false, hash: sha, avatarUrl: null, verifiedAccounts: [], urls: [] };
}

/**
 * Find a GitHub account by commit address.
 *
 * Every commit carries the author's email, and GitHub indexes it. An address
 * that has authored one public commit is therefore resolvable to an account —
 * which is how a great many "anonymous" addresses get named, because the person
 * configured git years ago and forgot.
 *
 * The unauthenticated search API allows only ten requests a minute *per source
 * address*, and on shared egress that budget is routinely already spent, so a
 * token is worth configuring if this matters.
 */
async function githubByEmail(email, env) {
  const headers = {
    accept: 'application/vnd.github+json',
    ...(env.GITHUB_TOKEN ? { authorization: `Bearer ${env.GITHUB_TOKEN}` } : {}),
  };

  const body = await getJson(
    `https://api.github.com/search/users?q=${encodeURIComponent(`${email.value} in:email`)}&per_page=5`,
    { source: 'api.github.com', timeout: 9000, headers },
  );

  const candidates = (body.items ?? []).slice(0, 3);

  // GitHub's `in:email` qualifier matches loosely — searching "m@example.com"
  // happily returns a user called "m". Reporting that as a hit would be worse
  // than reporting nothing, so each candidate is confirmed against the address
  // actually published on its profile, and only an exact match is asserted.
  const confirmed = await Promise.allSettled(
    candidates.map(async (item) => {
      const profile = await getJson(`https://api.github.com/users/${encodeURIComponent(item.login)}`, {
        source: 'api.github.com',
        timeout: 8000,
        headers,
      });
      return { item, profile };
    }),
  );

  const matches = confirmed.map((outcome, i) => {
    const item = candidates[i];
    const profile = outcome.status === 'fulfilled' ? outcome.value.profile : null;
    const publishedEmail = (profile?.email ?? '').toLowerCase();
    const exact = publishedEmail === email.value.toLowerCase()
      || publishedEmail === email.canonical.toLowerCase();

    return {
      platform: 'GitHub',
      username: item.login,
      url: item.html_url,
      avatarUrl: item.avatar_url ?? null,
      type: item.type ?? null,
      // Everything below only exists when the profile fetch succeeded.
      name: profile?.name ?? null,
      company: profile?.company ?? null,
      location: profile?.location ?? null,
      blog: profile?.blog || null,
      publicEmail: profile?.email ?? null,
      createdAt: profile?.created_at?.slice(0, 10) ?? null,
      publicRepos: profile?.public_repos ?? null,
      followers: profile?.followers ?? null,
      confirmed: exact,
      confirmation: exact
        ? 'The address is published on this account\'s public profile.'
        : profile
          ? 'Returned by search but the account publishes a different address (or none). Treat as a lead, not a match.'
          : 'Returned by search; the profile could not be fetched to confirm it.',
    };
  });

  return {
    matched: matches.some((m) => m.confirmed),
    candidates: matches.length,
    total: body.total_count ?? matches.length,
    matches,
  };
}

/**
 * What the domain's DNS says about whether mail to this address can arrive, and
 * who would handle it.
 *
 * This is the closest thing to deliverability that can be established without
 * touching the mail server: no MX and no A record means nothing can be
 * delivered at all, and the MX names identify the operator holding the mailbox.
 */
async function mailPosture(domain) {
  const [mx, a, spf, dmarc, mtaSts] = await Promise.allSettled([
    resolve(domain, 'MX'),
    resolve(domain, 'A'),
    resolve(domain, 'TXT'),
    resolve(`_dmarc.${domain}`, 'TXT'),
    resolve(`_mta-sts.${domain}`, 'TXT'),
  ]);

  const mxRecords = mx.status === 'fulfilled' ? mx.value.records : [];
  const hosts = mxRecords
    .map((record) => {
      const [priority, ...rest] = record.split(/\s+/);
      const value = Number(priority);
      return {
        // `|| null` would be wrong here: priority 0 is both valid and common,
        // and it is the highest priority there is.
        priority: Number.isFinite(value) ? value : null,
        host: rest.join(' ').replace(/\.$/, '').toLowerCase(),
      };
    })
    .filter((entry) => entry.host && entry.host !== '.')
    .sort((x, y) => (x.priority ?? Infinity) - (y.priority ?? Infinity));

  const txt = spf.status === 'fulfilled' ? spf.value.records : [];
  const spfRecord = txt.find((r) => r.toLowerCase().startsWith('v=spf1')) ?? null;
  const dmarcRecord = (dmarc.status === 'fulfilled' ? dmarc.value.records : [])
    .find((r) => r.toLowerCase().startsWith('v=dmarc1')) ?? null;

  // A null MX record (RFC 7505) is an explicit declaration that the domain
  // accepts no mail at all — different from simply having none configured.
  const nullMx = mxRecords.some((r) => /\s\.$|\s\.\s*$/.test(r) || r.trim().endsWith(' .'));

  return {
    hasMx: hosts.length > 0,
    nullMx,
    mxHosts: hosts.slice(0, 8),
    provider: mailProvider(...hosts.map((h) => h.host)),
    // Without MX, RFC 5321 falls back to the A record.
    fallbackA: !hosts.length && a.status === 'fulfilled' ? a.value.records.slice(0, 3) : [],
    spf: spfRecord,
    dmarc: dmarcRecord,
    dmarcPolicy: dmarcRecord?.match(/\bp=([a-z]+)/i)?.[1] ?? null,
    mtaSts: mtaSts.status === 'fulfilled'
      ? (mtaSts.value.records.find((r) => r.toLowerCase().startsWith('v=stsv1')) ?? null)
      : null,
    deliverable: hosts.length > 0 || (!hosts.length && a.status === 'fulfilled' && a.value.records.length > 0),
  };
}

/**
 * DKIM selectors on the address's domain — the platforms authorised to send as
 * it. On a corporate address this maps the organisation's mail stack; on a
 * consumer domain it simply confirms the provider.
 */
async function sendingPlatforms(domain) {
  const candidates = DKIM_SELECTORS.slice(0, 12);
  const results = await resolveBatch(
    candidates.map((c) => `${c.selector}._domainkey.${domain}`),
    'TXT',
  );

  const found = [];
  results.forEach((result, i) => {
    if (result.records.some((r) => /v=DKIM1|[;\s]p=/i.test(r))) {
      found.push({ selector: candidates[i].selector, platform: candidates[i].platform });
    }
  });

  return { checked: candidates.length, found, platforms: [...new Set(found.map((f) => f.platform))] };
}

/**
 * Registration age of the address's domain.
 *
 * A domain registered last week is the strongest single signal that an address
 * is disposable or fraudulent, and it is invisible from the address alone.
 */
async function domainAge(email) {
  // Consumer providers have decades-old registrations; the lookup costs a round
  // trip and tells you nothing you did not already know.
  if (FREE_MAIL_DOMAINS.has(email.domain)) {
    return { skipped: true, reason: 'A well-known consumer mailbox provider; registration age is not informative.' };
  }

  const apex = email.labels.slice(-2).join('.');
  const body = await rdap.lookup('domain', apex);
  const created = rdap.eventDate(body.events, 'registration');
  const roles = rdap.entitiesByRole(body.entities);

  return {
    skipped: false,
    domain: apex,
    created,
    expires: rdap.eventDate(body.events, 'expiration'),
    ageDays: created ? Math.floor((Date.now() - new Date(created)) / 86_400_000) : null,
    registrar: roles.registrar?.name ?? roles.registrar?.organization ?? null,
    registrant: roles.registrant?.organization ?? roles.registrant?.name ?? null,
  };
}

/** Have I Been Pwned. The only authoritative breach source, and it needs a key. */
async function haveIBeenPwned(address, key) {
  try {
    const body = await getJson(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(address)}?truncateResponse=false`,
      {
        source: 'haveibeenpwned.com',
        timeout: 10000,
        headers: { 'hibp-api-key': key, accept: 'application/json' },
      },
    );

    const breaches = (Array.isArray(body) ? body : []).map((b) => ({
      name: b.Title ?? b.Name,
      domain: b.Domain ?? null,
      date: b.BreachDate ?? null,
      accounts: b.PwnCount ?? null,
      // What was exposed matters far more than the count: an address in a
      // marketing-list breach is different from one with a password beside it.
      data: b.DataClasses ?? [],
      verified: b.IsVerified ?? null,
      sensitive: b.IsSensitive ?? null,
    }));

    return {
      breached: breaches.length > 0,
      count: breaches.length,
      breaches: breaches.sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '')),
      exposedData: [...new Set(breaches.flatMap((b) => b.data))],
    };
  } catch (err) {
    // HIBP answers "not found" with a 404, which is the clean result.
    if (err.status === 404) return { breached: false, count: 0, breaches: [], exposedData: [] };
    throw err;
  }
}

async function virusTotalDomain(domain, key) {
  const body = await getJson(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
    source: 'virustotal.com',
    headers: { 'x-apikey': key },
  });
  const stats = body.data?.attributes?.last_analysis_stats ?? {};
  return {
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
  };
}

/* ------------------------------------------------------------ classification */

/**
 * What kind of address is this?
 *
 * Everything downstream depends on the answer. A role address at a company
 * domain is a team inbox and will never have a Gravatar; a throwaway is not
 * worth attributing at all; an alias is a real person deliberately not using
 * their real address.
 */
function classify(email, data) {
  const local = email.local.toLowerCase().split('+')[0];
  const domain = email.domain;

  const isFree = FREE_MAIL_DOMAINS.has(domain);
  const isDisposable = DISPOSABLE_MAIL_DOMAINS.has(domain);
  const isAlias = ALIAS_MAIL_DOMAINS.has(domain) || [...ALIAS_MAIL_DOMAINS].some((d) => domain.endsWith(`.${d}`));
  const isRole = ROLE_LOCAL_PARTS.has(local);
  const typo = MAIL_TYPOS[domain] ?? null;

  const kind = isDisposable ? 'disposable'
    : isAlias ? 'alias / forwarder'
      : isRole ? 'role account'
        : isFree ? 'consumer mailbox'
          : 'organisation mailbox';

  const meaning = {
    disposable: 'A throwaway mailbox from a service that mints addresses on demand. It identifies nobody and is usually dead within the hour.',
    'alias / forwarder': 'A privacy alias that forwards to a real mailbox elsewhere. A real person is behind it, but the address deliberately reveals nothing about them.',
    'role account': 'A shared function inbox read by a team, not a person. Attributing it to an individual is a category error.',
    'consumer mailbox': 'A personal address at a public provider. The domain says nothing about the owner; only the address itself is a lead.',
    'organisation mailbox': 'An address at a domain someone registered. The domain is the strongest lead here — it can be looked up in full.',
  }[kind];

  return {
    kind,
    meaning,
    isFreeProvider: isFree,
    isDisposable,
    isAlias,
    isRoleAccount: isRole,
    likelyTypo: typo,
    // A "+tag" is chosen per-signup and often names the service it was used for.
    subAddressTag: email.tag,
    provider: data.mail?.provider ?? null,
  };
}

/**
 * Usernames worth trying on the username lookup.
 *
 * People reuse handles far more than they reuse addresses, so the local part is
 * usually the same string they registered elsewhere. Splitting the common
 * separator forms covers the variants they are likely to have used.
 */
function usernameCandidates(email) {
  const base = email.local.toLowerCase().split('+')[0];
  const candidates = new Set([base]);

  candidates.add(base.replace(/[._-]/g, ''));
  const parts = base.split(/[._-]/).filter((p) => p.length > 1);
  if (parts.length > 1) {
    candidates.add(parts.join(''));
    candidates.add(parts[0]);
    candidates.add(parts[parts.length - 1]);
  }

  return [...candidates].filter((c) => c.length >= 2 && c.length <= 39 && /^[a-z0-9][a-z0-9._-]*$/.test(c)).slice(0, 6);
}

/** Everything that names, or points at, a human. */
function identity(data) {
  const names = [];
  const add = (value, source, confidence) => {
    if (!value) return;
    const clean = String(value).trim();
    if (clean.length < 2 || clean.length > 120) return;
    if (names.some((n) => n.value.toLowerCase() === clean.toLowerCase())) return;
    names.push({ value: clean, source, confidence });
  };

  const gravatar = data.gravatar;
  if (gravatar?.exists) {
    add(gravatar.name, 'Gravatar profile name', 'medium');
    add(gravatar.displayName, 'Gravatar display name', 'medium');
    add(gravatar.username, 'Gravatar username', 'medium');
    add(gravatar.company, 'Gravatar employer', 'low');
  }
  for (const match of data.github?.matches ?? []) {
    // A confirmed match published this address itself; an unconfirmed one is a
    // fuzzy search hit and must not be presented as the same kind of fact.
    add(match.username, 'GitHub account', match.confirmed ? 'high' : 'low');
    if (match.confirmed) {
      add(match.name, 'GitHub profile name', 'medium');
      add(match.company, 'GitHub employer', 'low');
    }
  }

  const accounts = [
    ...(gravatar?.verifiedAccounts ?? []).map((a) => ({
      platform: a.platform, username: a.username, url: a.url,
      source: 'Gravatar', verified: a.verified,
    })),
    ...(data.github?.matches ?? []).map((m) => ({
      platform: 'GitHub', username: m.username, url: m.url,
      source: 'GitHub user search', verified: m.confirmed,
    })),
  ];

  return {
    names,
    best: names[0] ?? null,
    accounts,
    links: (gravatar?.urls ?? []).filter((u) => u.url),
    location: gravatar?.location ?? null,
    bio: gravatar?.aboutMe ?? null,
  };
}

/* --------------------------------------------------------------- assessment */

function assess(email, data, classification) {
  const findings = [];

  if (classification.likelyTypo) {
    findings.push({
      level: 'warn',
      title: `"${email.domain}" looks like a typo for "${classification.likelyTypo}"`,
      detail: 'Domains a character away from a major provider are registered deliberately, to catch misdirected mail. Confirm the address before using it.',
    });
  }

  if (classification.isDisposable) {
    findings.push({
      level: 'warn',
      title: 'Disposable mailbox provider',
      detail: `${email.domain} mints throwaway addresses on demand. The address identifies nobody and is probably already dead.`,
    });
  }
  if (classification.isAlias) {
    findings.push({
      level: 'info',
      title: 'Privacy alias',
      detail: 'This forwards to a real mailbox the owner is deliberately not showing. There is a real person behind it, but the address is a dead end by design — the alias is disposable, the person is not.',
    });
  }
  if (classification.isRoleAccount) {
    findings.push({
      level: 'info',
      title: `Role account (${email.local.split('+')[0]})`,
      detail: 'A shared inbox read by whoever is on duty. Do not attribute it to an individual.',
    });
  }
  if (classification.subAddressTag) {
    findings.push({
      level: 'info',
      title: `Sub-address tag "+${classification.subAddressTag}"`,
      detail: 'The owner tagged this address when they handed it out, which usually names the service it was given to. If it appears somewhere unexpected, that address was shared or leaked.',
    });
  }

  const gravatar = data.gravatar;
  if (gravatar?.exists) {
    const detail = [
      gravatar.name || gravatar.displayName,
      gravatar.location,
      gravatar.company,
      gravatar.verifiedAccounts?.length ? `${gravatar.verifiedAccounts.length} linked account(s)` : null,
    ].filter(Boolean).join(' · ');
    findings.push({
      level: 'ok',
      title: 'Gravatar profile exists',
      detail: `${detail || 'A profile exists but carries no detail.'} The owner created this and chose what it says, so the accounts listed on it are theirs by their own declaration.`,
    });
  } else if (gravatar) {
    findings.push({
      level: 'info',
      title: 'No Gravatar profile',
      detail: 'No public profile is registered for this address. That is the normal case and is not evidence the address is unused.',
    });
  }

  const confirmedGithub = (data.github?.matches ?? []).filter((m) => m.confirmed);
  const unconfirmedGithub = (data.github?.matches ?? []).filter((m) => !m.confirmed);
  if (confirmedGithub.length) {
    findings.push({
      level: 'ok',
      title: `Published on ${confirmedGithub.length} GitHub account(s)`,
      detail: confirmedGithub.map((m) => `${m.username}${m.name ? ` (${m.name})` : ''}${m.company ? ` — ${m.company}` : ''}`).join(', ')
        + '. Each of these accounts publishes this exact address on its public profile, so the link is the account owner\'s own declaration.',
    });
  } else if (unconfirmedGithub.length) {
    findings.push({
      level: 'info',
      title: `${unconfirmedGithub.length} unconfirmed GitHub search hit(s)`,
      detail: unconfirmedGithub.map((m) => m.username).join(', ')
        + '. GitHub\'s email search matches loosely and none of these accounts publish this address, so they are leads to check rather than matches.',
    });
  }

  const mail = data.mail;
  if (mail) {
    if (mail.nullMx) {
      findings.push({
        level: 'danger',
        title: 'Domain publishes a null MX',
        detail: 'RFC 7505 null MX is an explicit declaration that this domain accepts no mail. Nothing sent to this address can be delivered.',
      });
    } else if (!mail.deliverable) {
      findings.push({
        level: 'danger',
        title: 'Domain has no mail server',
        detail: 'No MX record and no A record to fall back on, so mail to this address cannot be delivered anywhere.',
      });
    } else if (!mail.hasMx) {
      findings.push({
        level: 'warn',
        title: 'No MX record — delivery falls back to the A record',
        detail: `Mail would be attempted against ${mail.fallbackA.join(', ')}. This works but is unusual for a domain that actually handles mail.`,
      });
    } else {
      findings.push({
        level: 'ok',
        title: mail.provider ? `Mail handled by ${mail.provider}` : 'Domain accepts mail',
        detail: `${mail.mxHosts.length} MX host(s): ${mail.mxHosts.map((h) => h.host).join(', ')}.`
          + ' This confirms a mail server exists — it does not confirm this particular mailbox does.',
      });
    }

    if (!mail.dmarc) {
      findings.push({ level: 'info', title: 'Domain has no DMARC policy', detail: 'Mail claiming to come from this address is easier to spoof, and harder to disprove.' });
    }
  }

  const registration = data.registration;
  if (registration && !registration.skipped && registration.ageDays != null) {
    if (registration.ageDays < 90) {
      findings.push({
        level: 'warn',
        title: `Domain registered ${registration.ageDays} days ago`,
        detail: 'A very new domain behind an email address is one of the strongest fraud signals there is.',
      });
    } else {
      findings.push({
        level: 'info',
        title: `Domain registered ${registration.created?.slice(0, 10)}`,
        detail: `${Math.floor(registration.ageDays / 365)} years old${registration.registrar ? `, through ${registration.registrar}` : ''}.`
          + (registration.registrant ? ` Registrant: ${registration.registrant}.` : ''),
      });
    }
  }

  const breaches = data.breaches;
  if (breaches?.breached) {
    findings.push({
      level: 'warn',
      title: `Present in ${breaches.count} known breach(es)`,
      detail: `${breaches.breaches.slice(0, 6).map((b) => `${b.name} (${b.date?.slice(0, 4) ?? '?'})`).join(', ')}. `
        + `Exposed data across all of them: ${breaches.exposedData.slice(0, 10).join(', ')}.`,
    });
  } else if (breaches) {
    findings.push({ level: 'ok', title: 'Not in any known breach', detail: 'Have I Been Pwned has no record of this address.' });
  }

  if (data.dkim?.platforms?.length) {
    findings.push({
      level: 'info',
      title: 'Sending platforms on this domain',
      detail: data.dkim.platforms.filter((p) => p !== 'generic').join(', ') || 'Only generic selectors found.',
    });
  }

  if (!findings.some((f) => f.level === 'warn' || f.level === 'danger')) {
    findings.unshift({ level: 'ok', title: 'Nothing concerning', detail: 'The domain accepts mail and nothing about the address suggests it is disposable or fraudulent.' });
  }
  return findings;
}

function caveats(data, env) {
  const notes = [
    'No mailbox was contacted. Everything here comes from DNS, from public profile data keyed on a hash of the address, and from public code-hosting indexes. Whether this specific mailbox exists cannot be established without sending mail to it, which this tool will not do.',
  ];

  if (data.gravatar && !data.gravatar.exists) {
    notes.push('A missing Gravatar profile means only that the owner never created one. Most people have not.');
  }
  if (!env.HIBP_API_KEY) {
    notes.push('Breach checking is off. Have I Been Pwned is the only authoritative source and requires a paid API key; without it, nothing here says whether the address has been exposed.');
  }
  if (!env.GITHUB_TOKEN) {
    notes.push('GitHub search is running unauthenticated, which allows ten queries a minute per source address. On shared egress that budget is often already spent by unrelated traffic, so an empty result is not conclusive. Setting GITHUB_TOKEN removes the limit.');
  }
  notes.push('Address hashes are computed locally and the address itself is never sent to Gravatar — only its digest. Note that this cuts both ways: anyone holding a hash can test a guessed address against it, which is why hashing an email is not anonymisation.');

  return notes;
}

function pivots(email, addressMd5, addressSha256) {
  const quoted = encodeURIComponent(`"${email.value}"`);
  return [
    { label: 'Google', url: `https://www.google.com/search?q=${quoted}` },
    { label: 'DuckDuckGo', url: `https://duckduckgo.com/?q=${quoted}` },
    { label: 'Have I Been Pwned', url: `https://haveibeenpwned.com/account/${encodeURIComponent(email.value)}` },
    { label: 'Gravatar', url: `https://gravatar.com/${addressSha256}` },
    { label: 'Gravatar (MD5)', url: `https://gravatar.com/${addressMd5}` },
    { label: 'GitHub commits', url: `https://github.com/search?q=${encodeURIComponent(email.value)}&type=commits` },
    { label: 'GitHub users', url: `https://github.com/search?q=${encodeURIComponent(`${email.value} in:email`)}&type=users` },
    { label: 'Epieos', url: `https://epieos.com/?q=${encodeURIComponent(email.value)}` },
    { label: 'Hunter.io', url: `https://hunter.io/email-verifier/${encodeURIComponent(email.value)}` },
    { label: 'Domain lookup', url: `?type=domain&q=${encodeURIComponent(email.domain)}` },
    { label: 'Pastes via Google', url: `https://www.google.com/search?q=${encodeURIComponent(`"${email.value}" (site:pastebin.com OR site:gist.github.com OR site:throwbin.io)`)}` },
    { label: 'Documents via Google', url: `https://www.google.com/search?q=${encodeURIComponent(`"${email.value}" (filetype:pdf OR filetype:xlsx OR filetype:csv)`)}` },
  ];
}
