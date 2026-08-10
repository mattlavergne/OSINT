# GhostTrace

A passive OSINT reconnaissance console for **phone numbers**, **email addresses**, **usernames**, **domains**, **IP addresses** and **autonomous systems**, with a web interface.

It is a modern rebuild of the ideas in [GhostTrack](https://github.com/HunxByts/GhostTrack), which was last updated in 2022. GhostTrack was a Python CLI that printed three lookups to a terminal; GhostTrace keeps the premise — cheap, keyless, public-source reconnaissance — and rebuilds it as a deployable web app with a real API, honest data provenance, and sources that still exist.

The organising idea is that a lookup should tell you what a signal *means*, not just what it says. Free geolocation databases disagree with each other by hundreds of kilometres, so the disagreement is measured and shown. A carrier record describes the original range allocation, not today's operator, so it is labelled as such. A username found on nine platforms is not nine accounts belonging to one person, so the self-reported names are correlated and the conflicts are flagged. Where a source cannot answer honestly, it says so rather than guessing.

---

## What changed from GhostTrack

| | GhostTrack (2022) | GhostTrace |
|---|---|---|
| Interface | Python CLI, ANSI art | Web app + JSON API |
| Modules | IP, phone, username | IP, phone, username, **domain**, **email**, **ASN** |
| IP data | `ipwho.is` geolocation only | Four geolocation providers with their disagreement measured + operator geofeed + RDAP netblock owner + abuse contact + reverse DNS + BGP routing and history + DNS blocklists + Tor directory + open ports + known CVEs |
| Phone data | `phonenumbers` parse | libphonenumber validation + line type + NANP rate centre, switch and block holder + carrier + timezones + business attribution |
| WHOIS | none | RDAP (the structured IETF replacement for port-43 WHOIS) |
| Username module | 25 hardcoded sites, checked by HTTP 200 | 17 platforms with real existence APIs, cross-correlated — see below |
| Failure mode | one dead API kills the run | per-source isolation; a dead source is reported, the rest still render |
| Data honesty | coordinates printed as fact | precision labelled, provider disagreement quantified, portability and allocation caveats stated inline |

**The username module, rebuilt rather than restored.** The original worked by requesting 25 profile URLs and treating HTTP 200 as "account exists". That produces false positives on every site that returns 200 for a missing profile (most of them, by 2026) and false negatives on everything behind Cloudflare or a login wall. The rebuild only checks platforms that expose an API with unambiguous existence semantics — a user object or a 404, with no middle case to guess at. Platforms that cannot be checked honestly are **listed as links for a human to open**, not guessed at, and a platform that errors is reported as *unknown*, never as *absent*. That distinction is the whole difference between a useful answer and a misleading one.

---

## The six lookups

### Phone
Google's libphonenumber rules via `libphonenumber-js`, plus the geocoding, carrier and timezone datasets.

- Validity and possibility, distinguished — a plausible length is not an allocated range
- Line type: mobile, fixed line, VoIP, toll-free, premium rate, pager, …
- Geographic area the range is allocated to, and the carrier it was originally allocated to
- Every timezone the number could sit in, with current local time
- E.164 / international / national / RFC 3966 formats
- Search pivots (Google, Truecaller, WhatsApp, Telegram) — links are *built*, never followed
- **North American numbering plan data** from the LERG, via the Local Calling Guide's keyless XML API. This is the single biggest free upgrade available for a US or Canadian number, and almost nothing surfaces it: the **rate centre**, the physical central-office **switch** the block homes on (CLLI code, switch name and model), the **LATA**, the **operating company number**, whether the holder is the incumbent carrier or a competitive one, whether the block is a full 10,000-number allocation or a pooled 1,000-block, and the rate centre's own coordinates. For a landline that is a real fix on a telephone exchange rather than a database's guess at a city.
- **Wholesale-carrier detection.** The LERG names the block holder outright, so a number sold through Bandwidth, Twilio, Telnyx, Onvoy or similar is identified as such. These carriers provision numbers programmatically with no address verification, which is why they sit behind most spoofed and disposable caller IDs — and it is a fact about the number, not an inference from its shape.
- **Reverse name lookup** for businesses: OpenStreetMap, SEC EDGAR and Wikipedia full-text, all free and keyless, merged into a ranked attribution list with per-source confidence
- **Every written form of the number**, because search engines, forums and leaked datasets each spell numbers differently and a search for one spelling misses the rest
- Optional CNAM caller-ID name via Twilio, and search footprint via Brave (see below)

Validity, location and carrier each carry a stated caveat, because all three are routinely over-read. A valid number need not be in service; an allocation area is not a device location; number portability means the carrier may be years out of date.

### Domain
- **RDAP** registration: registrar, IANA ID, creation/expiry, age, EPP status codes translated into English, DNSSEC delegation, abuse contact, and redaction-aware registrant handling
- **DNS**: A, AAAA, MX, NS, TXT, SOA, CAA, DS over DoH (Cloudflare primary, Google fallback), with CAA decoded out of RFC 3597 generic form
- **Email authentication**: SPF with policy qualifier and the 10-lookup limit checked, DMARC with enforcement and alignment, MTA-STS, BIMI
- **Subdomains** from three parallel keyless sources: Cert Spotter, crt.sh and HackerTarget
- **Certificates**: recent issuance and issuer distribution from Certificate Transparency
- **Hosting**: each resolved address enriched with geolocation, ASN and open ports
- **HTTP posture**: one ordinary HTTPS GET of the site root to read HSTS, CSP, X-Frame-Options, CDN fingerprint and disclosed server software
- **Service verification TXT records**, which reveal the SaaS platforms an organisation uses
- **Attribution**: candidate organisation names assembled from RDAP, `og:site_name`, the copyright line and the page title — each tagged with its source and a confidence level, because a registry field and a marketing title are not equally trustworthy
- **Contacts**: `security.txt` (RFC 9116), RDAP abuse contact, and addresses published in the page
- **Linked social profiles** and **analytics IDs** (GA4, UA, GTM, Meta Pixel, Hotjar) — a shared measurement ID across sites is strong evidence of a common operator
- **Archive history**: first and last Wayback capture, which exposes domains re-registered long after their content first appeared
- **Lookalike domains**: typosquat permutations from dnstwister, with a bounded subset resolved to show which are actually registered — `github.com` surfaces `qithub.com` and a punycode homoglyph, both live
- **urlscan.io history**: public scan record, page titles and the addresses urlscan actually observed serving the site, which can differ from what it resolves to now
- **DKIM selector discovery** (deep scan): DKIM keys live at `<selector>._domainkey`, and the selector is chosen by whoever sends the mail, so the selectors that resolve are a direct list of every platform authorised to send as the domain — several of which appear nowhere else in DNS. Weak keys (under 1024 bits) and revoked selectors are flagged.
- **Technology fingerprinting** from response headers, cookie names and page source — CMS, framework, backend, web server, CDN, WAF, analytics, payments and identity providers. Deliberately a small high-precision set rather than a Wappalyzer clone: a fingerprint that guesses wrong is worse than none.
- **Favicon hash** (MurmurHash3 of the base64-encoded icon, the value Shodan, Censys and FOFA index). Operators almost never change the icon when they move or rename infrastructure, so searching this hash finds every other host serving the same site — including **the origin server behind a CDN**, which is otherwise one of the hardest things to establish from outside.
- **schema.org structured data**: where a site publishes an `Organization` block it hands over the legal name, street address, telephone, founding date, tax ID and its own list of official profiles (`sameAs`). Self-declared, machine-readable, routinely present and almost never read.
- **Subdomain mapping** (deep scan): the discovered names are ranked by how likely the prefix is to front something interesting, resolved, and grouped by address. Two findings fall out — **subdomain takeover candidates** (a dangling CNAME into a SaaS platform that no longer serves it) and **origin-leak candidates** (names resolving outside the CDN's address set, which is how a CDN's protection gets bypassed).
- **Domains sharing a certificate**: names on the same TLS certificate that belong to a different registrable domain. A certificate covering two domains was issued to whoever proved control of both, which makes it one of the strongest ownership links in public logs.
- **Conventional public files**: `robots.txt` (the paths an operator asks crawlers to avoid are reliably the ones they consider sensitive) and `ads.txt` (the ad-network publisher accounts a site sells through — the same DIRECT account ID on another site is a hard ownership link between them)
- **SRV service discovery** (deep scan), **DNSSEC posture** including the signed-but-not-delegated misconfiguration, **wildcard DNS detection** (which decides whether subdomain resolution proves anything at all), and the **redirect chain** rather than just the destination
- **Infrastructure provider identification**: who runs the mail, the DNS, the edge and the sending platforms — which is the shape that tells you which organisations to ask, and which of them would hold logs

### IP
- Geolocation **with a precision label** (city / region / country) so coordinates are not mistaken for an address
- RDAP: netblock, CIDR, allocation type, registry, registrant, abuse contact and phone
- Reverse DNS (PTR)
- Shodan **InternetDB** (free, keyless): open ports, known CVEs, observed hostnames, software CPEs
- Hosting/CDN detection, which reframes what the geolocation actually means
- **BGP routing** from RIPEstat: announced prefix, origin AS and holder, announcement status — who announces a prefix is harder to falsify than a geolocation record
- **Attack history** from SANS ISC DShield: how many networks the address has been logged attacking, event counts, first/last seen and threat-feed listings — the signal AbuseIPDB gives you only after you register, here without a key
- **Network operator profile** from PeeringDB: how the operator describes its own network — type, scope, peering policy, prefix counts, IRR AS-SET
- **Co-hosted domains** on the same address, which names the operator on dedicated hosting and flags shared infrastructure when it is not
- Non-routable input (RFC 1918, loopback, CGNAT, link-local) short-circuits with an explanation instead of four upstream errors
- **Geolocation consensus.** Four providers run in parallel rather than the first success winning, and the **widest disagreement between them is reported in kilometres**. This is the honest measure of what a free geolocation answer is worth: `8.8.8.8` comes back as San Jose, Ashburn and Mountain View — 3,859 km apart — and no single provider will ever tell you that.
- **RFC 8805 geofeed.** A geofeed is a CSV the *network operator themselves* publishes, mapping their own prefixes to the country, region and city they are actually deployed in. Where one exists it is categorically better evidence than any commercial database, because the operator is the only party who actually knows. Discovered from the RDAP record — from a typed link or, as RFC 9092 also allows and most operators actually use, a bare `geofeed:` line in a remark.
- **DNS blocklists**, queried the way a mail server queries them. This is what a receiving server sees when the address tries to deliver, and it is more direct than any vendor score: a Spamhaus PBL listing says *this is an end-user address*, an XBL listing says *this machine is compromised*. Zones that refuse queries from public resolvers signal that refusal **as a listing**, in `127.255.255.x` — so that case is detected and reported as "not usable from here" rather than flagging every address on the internet.
- **Tor directory status** from Onionoo, the Tor Project's own source. If the address is an exit relay, the traffic behind it belongs to somebody else entirely and no amount of geolocation will ever point at a person.
- **Routing history** (deep scan): a prefix that has changed origin AS was transferred, leased, or hijacked. Nothing in a point-in-time lookup can show that.
- **Reverse-DNS intelligence.** Cloud PTR records are machine-generated and encode more than the operator name — `ec2-….eu-west-2.compute.amazonaws.com` pins the AWS region, which is more precise than any geolocation database will be for that address.
- **A classification with its evidence**: datacenter, residential, mobile, proxy/VPN or Tor, with the signals that led there and a plain statement of what it means for everything else in the report. A city on a datacenter address is a rack; a city on a residential address is roughly a person.

### Email

- **Gravatar profile**, keyed by a hash computed locally so the address itself is never sent anywhere. Where the owner filled it in, this returns a display name, location, employer, bio and — most valuable — **the accounts they verified control of**, which is a ready-made pivot set no amount of guessing would produce.
- **GitHub accounts** publishing the address. Search matches loosely, so every candidate is confirmed against the address on its own public profile; only an exact match is reported as a match, and the rest are labelled leads.
- **Mail posture**: MX hosts and the provider behind them, RFC 7505 null-MX (an explicit declaration that the domain accepts no mail), A-record fallback, SPF, DMARC and MTA-STS
- **Domain registration age**, the strongest single fraud signal an address carries and one that is invisible from the address alone
- **Classification** — organisation mailbox, consumer mailbox, role account, privacy alias or disposable — each with a statement of what it means. An alias is a real person deliberately not showing their mailbox; a role account is a team and attributing it to an individual is a category error.
- **Typo detection** against the major consumer providers, since domains a character away from `gmail.com` are registered deliberately to catch misdirected mail
- **Sub-address tags**: a `+tag` is chosen per-signup and usually names the service the address was given to, so finding it somewhere unexpected means the address was shared or leaked
- **Username candidates** derived from the local part, one click from a username lookup
- Optional breach exposure via Have I Been Pwned

Nothing here probes the mailbox. SMTP verification is not possible from a Worker, is unreliable against modern mail servers, and would generate traffic to a third party on the user's behalf, so the report says what DNS supports and stops there.

### Username

- 17 platforms with **real existence APIs** — GitHub, GitLab, Codeberg, npm, Hacker News, Reddit, Lobsters, Bluesky, Mastodon, Keybase, Wikipedia, Chess.com, Steam, Twitch, Docker Hub, Telegram and Gravatar
- **Profile detail, not just a checkmark**: display name, bio, location, employer, join date, follower count and published links, because a hit that says only "taken" answers nothing
- **Cross-platform correlation.** The self-reported names are tallied across accounts, so agreement on four platforms reads as evidence and disagreement is flagged as the warning it is. Registration dates are laid out together, because they are the cheapest way to separate a long-standing owner from someone who recently claimed the same handle.
- **Keybase proofs**, which are signed statements posted on the other platform and therefore the only *verifiable* account links available here, distinguished in the output from merely self-declared ones
- **Platforms that cannot be checked honestly are not checked.** X, Instagram, TikTok, Facebook, LinkedIn, YouTube and others serve login walls, bot challenges or soft-404s to server-side requests. They are handed over as links with the reason, which is what PhoneInfoga does for phone numbers and is the intellectually honest position.
- A platform that errors is reported as **unknown, never as absent**

### ASN

- **Registry record**: the legal holder, allocation dates, status and contacts, from the authoritative RDAP server for that number range
- **Every announced prefix**, with the total address count — because prefix count alone is misleading, a `/16` and a `/24` each counting once
- **Upstream transit providers**: the networks that carry this one to the rest of the internet. They hold a contract with its operator, which makes them the effective place to escalate abuse — and for anything bulletproof-hosting shaped, that list is the finding.
- **Peers** and **internet-exchange presence**, the closest thing an AS has to a physical footprint: equipment in those buildings, in those countries
- **Every published route to a human**, gathered from RDAP, BGPView and PeeringDB and ranked by role, because where a netblock's own record is stale or redacted the AS-level abuse address usually is not
- Private, reserved and documentation ranges short-circuit with an explanation instead of four upstream errors

---

## Data sources

Every source below is free and **needs no API key**.

| Source | Used for |
|---|---|
| [ipwho.is](https://ipwho.is) → [ip-api.com](https://ip-api.com) → [RIPEstat](https://stat.ripe.net/) | IP geolocation, tried in that order |
| [IANA RDAP bootstrap](https://data.iana.org/rdap/) | Authoritative RDAP server per address range and TLD |
| [rdap.org](https://rdap.org) | RDAP redirector, used only as a fallback |
| [Cloudflare DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) / [Google DoH](https://developers.google.com/speed/public-dns/docs/doh) | All DNS resolution |
| [Shodan InternetDB](https://internetdb.shodan.io) | Open ports, CVEs, hostnames |
| [Cert Spotter](https://sslmate.com/ct_search_api/) | Certificate Transparency (fast) |
| [crt.sh](https://crt.sh) | Certificate Transparency (deep history) |
| [RapidDNS](https://rapiddns.io/) → [HackerTarget](https://hackertarget.com/) | Reverse-IP co-hosted domains |
| [HackerTarget](https://hackertarget.com/) | Passive DNS host search (one of three subdomain sources) |
| [RIPEstat](https://stat.ripe.net/) | BGP prefix, origin AS and announcement status |
| [SANS ISC DShield](https://isc.sans.edu/api/) | Firewall-log attack history and threat-feed listings |
| [PeeringDB](https://www.peeringdb.com/) | Network operator profile: type, scope, peering policy, IRR AS-SET |
| [urlscan.io](https://urlscan.io/) | Public scan history, observed addresses and page titles |
| [dnstwister](https://dnstwister.report/) | Lookalike domain permutations for typosquat detection |
| [archive.org](https://archive.org/help/wayback_api.php) | First and last archived capture |
| The site's own HTML | Title, org name, copyright entity, contacts, social profiles, analytics IDs |
| `/.well-known/security.txt` | Published security contact (RFC 9116) |
| [OpenStreetMap Overpass](https://overpass-api.de/) | Reverse phone → business/POI name, address, website and social handles |
| [SEC EDGAR full-text](https://efts.sec.gov/) | Reverse phone → US public company, confirmed against its filed number |
| [Local Calling Guide](https://localcallingguide.com/) | NANP rate centre, central-office switch, LATA, OCN and block holder |
| [Wikipedia](https://en.wikipedia.org/w/api.php) | Full-text search for a phone number in article text |
| libphonenumber | Phone validation, geocoding, carrier, timezones |
| [Gravatar](https://gravatar.com/) | Email → profile, name, location and verified accounts, keyed by hash |
| [GitHub API](https://docs.github.com/rest) | Email → account, and username existence with profile detail |
| [Onionoo](https://onionoo.torproject.org/) | Tor relay directory, from the Tor Project itself |
| [Spamhaus, SpamCop, Barracuda, SORBS, UCEPROTECT, blocklist.de](https://www.spamhaus.org/) | DNS blocklist membership over DoH |
| [BGPView](https://bgpview.io/) | RIR allocation, ASN profile, prefixes, peers, upstreams, exchanges |
| Operator-published [RFC 8805 geofeeds](https://www.rfc-editor.org/rfc/rfc8805) | The network operator's own statement of where a prefix is deployed |
| [Keybase](https://keybase.io/), [Bluesky](https://bsky.app/), [Mastodon](https://mastodon.social/), [GitLab](https://gitlab.com/), [Codeberg](https://codeberg.org/), [npm](https://www.npmjs.com/), [Hacker News](https://news.ycombinator.com/), [Lobsters](https://lobste.rs/), [Chess.com](https://www.chess.com/), [Steam](https://steamcommunity.com/), [Docker Hub](https://hub.docker.com/), [Telegram](https://t.me/) | Username existence, with profile detail and account proofs |

### Optional enrichment

These unlock extra panels. All are optional; nothing breaks without them.

```sh
npx wrangler secret put SHODAN_API_KEY       # service banners and versions per port
npx wrangler secret put VIRUSTOTAL_API_KEY   # vendor reputation for domains and IPs
npx wrangler secret put ABUSEIPDB_API_KEY    # abuse confidence score and report categories
npx wrangler secret put GREYNOISE_API_KEY    # internet-wide scanning vs targeted, for IPs
npx wrangler secret put TWILIO_ACCOUNT_SID   # CNAM caller-ID name for phone numbers
npx wrangler secret put TWILIO_AUTH_TOKEN
npx wrangler secret put BRAVE_SEARCH_API_KEY # search footprint for phone numbers
npx wrangler secret put HIBP_API_KEY         # breach exposure for email addresses
npx wrangler secret put GITHUB_TOKEN         # lifts GitHub's per-IP rate limit
```

`GITHUB_TOKEN` is worth setting even though nothing depends on it. Unauthenticated GitHub API requests are limited to 60 an hour and search to 10 a minute **per source address**, and on shared egress — a Worker, a VPN, a datacenter — that budget is routinely already spent by unrelated traffic. Without a token, an empty GitHub result is not evidence of anything.

For the Node server, set them as environment variables instead. See `.dev.vars.example`.

### On putting a name to a phone number

The answer splits cleanly in two, and it is worth being precise about which half you are in.

**Businesses and organisations — yes, free, from three angles.**

- **OpenStreetMap**, via Overpass. Where a business has been mapped with its phone number, this returns the name, category, brand, street address, website and a link to the OSM record. `+1 212-343-3355` resolves to Hard Rock Cafe, 1501 Broadway. Open data (ODbL), keyless.
- **SEC EDGAR full-text search**, for US public companies. Every registrant files its principal phone number, and the index is free, keyless and official. `+1 408 996 1010` resolves to Apple Inc. — and because a full-text hit alone is weak evidence (the number may appear in a filing for any reason), each candidate is confirmed against the phone on its own EDGAR profile. Only an exact match is reported as the filer's own number; everything else is labelled *mentioned in filings*.
- **Search footprint**, needing a free Brave Search API key. This runs the search a human would run and returns the real titles and snippets. It is what [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) automates only halfway — it builds dork URLs and leaves the searching to you. Reverse-lookup spam sites, which dominate these results and name nobody, are filtered out of the name candidates.

All name candidates are merged into one ranked list, each tagged with its source and a confidence band: **high** means the entity published this number as its own, **medium** means a maintained public dataset lists it, **low** means a search engine surfaced it. A name corroborated by independent sources ranks above one that is not.

**Individuals — no free source exists.** This is not a gap in the implementation:

- Truecaller, Sync.me and Eyecon have no public API and prohibit scraping. The GitHub wrappers around Truecaller's mobile endpoints work by registering a handset and replaying its installation token, which violates their terms.
- The services that reliably return a subscriber name are data brokers (Whitepages, Spokeo, BeenVerified, Intelius). They are paid, and much of their corpus is the digitised residential white pages — which is exactly why it is no longer free.
- [PhoneInfoga](https://github.com/sundowndev/phoneinfoga), the best-known OSINT phone tool, does not return names either. It returns country, carrier and line type, then *generates search-engine dork URLs* for a human to follow. It is also now unmaintained. GhostTrace builds the same pivot links.

The one authoritative, lawful route to a subscriber name is **CNAM**, the caller-ID database carriers maintain, wired in here as optional Twilio credentials. Even that is US-centric, usually returns a business, and is frequently stale or empty for consumer mobile lines.

**Why the old phone book is not an API.** Residential white pages listed landline subscribers, and mobile numbers were never in them — no directory-listing obligation ever attached to mobile. As landlines collapsed and personal numbers went mobile, the directory stopped describing people. The digitised historical listings became the seed corpus of the data-broker industry rather than a public archive, and CCPA/CPRA and GDPR now force deletion and opt-out on what remains. Scanned directories survive in the Internet Archive, but as page images with inconsistent OCR — not queryable by number.

---

## Running it

```sh
npm install
npm run build      # generates public/data/phone/ from the libphonenumber datasets
npm test           # offline tests; no network, runs in well under a second
npm run test:live  # adds live upstream integration tests
```

Then either runtime:

```sh
npm run dev        # Cloudflare Worker, via wrangler
npm run dev:node   # plain Node server on http://127.0.0.1:8787
```

`npm run build` is not optional on a fresh clone — the ~8 MB of phone reference data is generated, not committed.

---

## Deploying to `mattlavergne.com/osint`

Everything below runs on the **Cloudflare free plan**. No paid features are involved.

The app deploys as a **single Worker** that serves the frontend from static assets *and* runs the API. There is no Pages project and no proxy Worker — one deploy, one moving part.

The zone already has `trafficmap-proxy` on `mattlavergne.com/*`, which is why every path currently returns the mattOS shell. Cloudflare resolves overlapping Worker routes by specificity, so `mattlavergne.com/osint*` wins for that path while `trafficmap-proxy` keeps serving everything else, unmodified.

### Option A — dashboard (Workers Builds)

**Workers & Pages → Create → Workers → Import a repository**, and pick this repo.

| Field | Value |
|---|---|
| Worker name | `osint` |
| Build command | `npm run build` |
| Deploy command | `npx wrangler deploy` |
| Path | `/` (the project is at the repo root) |

The build command is required — the ~8 MB of phone reference data under `public/data/phone/` is generated, not committed.

`wrangler.toml` already carries the routes, so the Worker attaches on first deploy. Nothing to configure by hand.

Two details that are easy to get wrong if you add the route by hand instead:

- **The trailing `*` is load-bearing.** `mattlavergne.com/osint` matches only that exact URL; every asset and API call underneath falls through to the other Worker, and the page renders with no stylesheet and no script.
- **Route paths are case-sensitive.** `/osint*` and `/OSINT*` are different routes. `wrangler.toml` registers both, and the Worker matches its prefix case-insensitively, so either spelling works.

### Option B — CLI

```sh
npm install
npm run deploy      # builds the reference data, then `wrangler deploy`
```

### Verify

```sh
curl -sI https://mattlavergne.com/osint           # 301 -> /osint/
curl -sS https://mattlavergne.com/osint/api/health
```

### How the mount works

The Worker is bound to a path, not a hostname, so requests arrive with `/osint` still attached. `src/worker.js` strips it before dispatch, which keeps routing identical to a root-mounted deployment, and redirects bare `/osint` to `/osint/` — without that trailing slash the browser resolves the app's relative asset and API URLs against the site root and nothing loads.

The strip is conditional, so the same build also works unprefixed on a `*.workers.dev` subdomain if you want to test before attaching the route. To mount somewhere else, change `PREFIX` in `src/worker.js` and the route in `wrangler.toml`; set `PREFIX` to `''` for a root-mounted deploy.

### Free-plan limits worth knowing

| Limit | Free plan | What this app uses |
|---|---|---|
| Worker requests | 100,000/day | one per lookup, plus one per static asset |
| Subrequests per request | 50 | standard scan: ~14 (IP), ~38 (domain), ~5 (phone). **Deep scan exceeds 50.** |
| CPU time per request | 10 ms | lookups are I/O-bound, not CPU-bound |
| Static asset requests | free, not billed as requests | — |
| Worker bundle size | 3 MB compressed | code only; the ~8 MB of phone data is assets, not bundle |

**The subrequest ceiling is why the depth switch exists.** Every lookup runs in one of two modes:

- **`standard`** (the default) is built to fit inside the free plan's 50-subrequest budget. A domain report sits at roughly 38, which leaves headroom for redirect hops and DoH fallbacks but not much more.
- **`deep`** turns on the enumeration passes — DKIM selectors, SRV services, subdomain resolution, takeover detection, routing history, ASN registry data. Individually cheap, collectively around 100 subrequests for a domain, which **needs the Workers Paid plan** (1,000 per request). On the free plan a deep scan will fail partway with `Too many subrequests`; the per-source isolation means you get a partial report rather than an error page, but the deep panels will be missing.

Deep scan is exposed as a toggle in the UI and as `&depth=deep` on the API. If you want to run deep scans on the free plan anyway, the biggest consumers are the subdomain resolution cap (`.slice(0, 25)` in `mapSubdomains`), the DKIM selector list (`DKIM_SELECTORS.slice(0, 16)`), the SRV service list, and the lookalike resolver limit — all in `src/lookups/domain.js`.

Latency matters as much as the ceiling. Every source runs concurrently, so a report costs roughly its slowest source, and each has an individual timeout chosen with that in mind. A domain report typically returns in about 3 seconds and an IP report in under 7.

### Alternative: a subdomain instead of a path

If you would rather not share the apex with the existing Worker, delete the `routes` block in `wrangler.toml`, deploy, and add `osint.mattlavergne.com` as a **Custom Domain** on the Worker. Cloudflare creates the DNS record and certificate. Then set `PREFIX = ''` in `src/worker.js`, since there is no longer a path prefix to strip.

### Alternative: Node behind nginx

If you move off Cloudflare later:

```sh
BASE_PATH=/osint PORT=8787 node server/index.mjs
```

Then include `deploy/nginx.conf` in the `server { }` block for the site. `BASE_PATH` strips the mount prefix, so routing is identical across all three runtimes.

## API

```
GET /api/phone?q=<number>&region=<ISO2>
GET /api/email?q=<address>
GET /api/username?q=<handle>
GET /api/domain?q=<domain>
GET /api/ip?q=<address>
GET /api/asn?q=<AS number>
GET /api/health
```

Every lookup endpoint accepts `&depth=standard|deep`. An unrecognised value degrades to `standard` rather than returning a 400 — a typo should cost you the extra panels, not the whole lookup.

`POST` with a JSON body works identically. Responses share a common envelope:

```jsonc
{
  "query":      { "type": "ip", "value": "8.8.8.8", "version": 4 },
  "assessment": [ { "level": "info", "title": "…", "detail": "…" } ],
  "pivots":     [ { "label": "Shodan", "url": "…" } ],
  "sources":    { "geo": { "ok": true }, "registry": { "ok": false, "error": "…" } },
  "elapsedMs":  312
}
```

`assessment` levels are `ok`, `info`, `warn`, `danger`. `sources` records every upstream that was consulted and why it failed if it did — a partial report is always labelled as one.

Status codes: `400` for invalid input (with a message written for a human), `404` for an unknown route, `502` when a lookup fails structurally. Individual dead sources do **not** produce an error status; they are reported in `sources`.

---

## Architecture

```
src/router.js            Runtime-agnostic router: Request in, Response out
src/lookups/{ip,domain,phone,email,username,asn}.js
src/lib/{http,dns,rdap,validate,providers,hash}.js
src/worker.js                Cloudflare Worker: static assets + API, mount-prefix aware
server/index.mjs             Node adapter (static files + API)
scripts/build-phone-data.mjs BSON → static JSON shards
public/                      Frontend: no framework, no build step
```

Both runtimes are thin adapters over one router, so the two deployments cannot drift apart.

Three decisions worth explaining:

**RDAP instead of WHOIS.** WHOIS needs a raw socket on port 43 and returns per-registrar freeform text. RDAP is JSON over HTTPS with a documented bootstrap, which is the only one of the two that works on Workers and the only one worth parsing.

**Phone reference data as static assets.** `libphonenumber-geo-carrier` reads its BSON with `fs` and `__dirname`, so it cannot run on Workers at all. `npm run build` converts it to JSON sharded by calling code, served as static files and fetched on demand — a UK lookup pulls a 20 KB shard, and China's 4 MB shard is only ever touched by Chinese numbers. Keeps ~15 MB out of the Worker bundle and gives both runtimes identical behaviour.

**Per-source isolation.** Every lookup runs its sub-queries concurrently under `Promise.allSettled` with individual timeouts. crt.sh times out on large domains routinely; that must degrade one panel, not the report.

**Fingerprints in one place.** `src/lib/providers.js` holds every pattern → label table — mail and DNS operators, hosting, PTR shapes, subdomain-takeover signatures, technology signatures, blocklist zones, DKIM selectors. Three lookups need the same knowledge, and keeping it in one module means they share one set of gaps rather than three.

**Hashes computed locally.** `src/lib/hash.js` implements MurmurHash3 and MD5 by hand — MurmurHash3 because bit-exact agreement with Shodan's index is the entire point (any deviation produces a number that is simply never found, including the base64 line-wrapping detail their crawler inherits from Python), and MD5 because `crypto.subtle` deliberately does not offer it and Gravatar's original URL scheme still uses it. Computing them locally also means an email address is never sent to Gravatar — only its digest.

**Provider chains, because shared egress breaks per-IP quotas.** On Workers the outbound source address is Cloudflare's, shared with every other customer, so any free API that meters per IP is effectively pre-exhausted before your request arrives. In production this showed up as ipwho.is returning 429, HackerTarget reporting its daily quota spent, and rdap.org — itself behind Cloudflare — failing the Worker-to-Cloudflare TLS handshake with 525. Geolocation, reverse-IP and RDAP therefore each run an ordered chain of independent providers and take the first success, and the answering provider is reported in the payload so a degraded result is visible rather than silent. Prefer unmetered infrastructure endpoints (RIPEstat, IANA, DoH resolvers, Shodan InternetDB) over commercial free tiers wherever both will do.

---

## What was considered and rejected

The [OSINT Framework](https://osintframework.com/) is the standard directory here, with 1,168 entries. Almost all of them are **web UIs for a human to type into**, not APIs — its Telephone Numbers branch is 22 links of which the queryable ones are Truecaller, Whitepages and similar, all of which prohibit automated access. Everything in it that is both free and machine-queryable has been folded in above. Specifically checked and rejected:

| Source | Why not |
|---|---|
| OpenCNAM | Free tier withdrawn; returns 401 without credentials |
| Numspy-Api | Endpoint dead (404) |
| ThreatMiner | API returns 500 |
| Whitepages / Spokeo / BeenVerified / Truecaller | Paid, and terms prohibit automated access |
| DuckDuckGo HTML, SearxNG public instances | Serve a bot challenge or captcha to datacenter addresses |
| Wikidata SPARQL (`P1329`, phone number) | The property exists but coverage is sparse and the stored values are mostly short codes written inconsistently, so an exact match essentially never hits. Wikipedia full-text search does the same job and actually returns results. |
| npm user registry endpoint | Now requires authentication (401), and the profile pages 403 server-side requests. The keyless maintainer search replaces it — a narrower question ("does this handle publish packages?"), reported as exactly that. |
| SMTP mailbox verification | Not possible from a Worker, unreliable against modern mail servers that accept-then-bounce, and it sends mail traffic to a third party on the user's behalf. |
| AWS/GCP/Azure published IP-range files | Correct, but the AWS file alone is ~1.5 MB to fetch and parse on every lookup. ASN holder, PTR shape and the DShield cloud field answer the same question for a fraction of the cost. |
| Reverse WHOIS by registrant email | Every provider is paid; the free tiers return counts without records. |

---

## Scope and ethics

Everything here reads public registries, public DNS, public certificate logs, and documents a site publishes at conventional public paths. The tool does not scan, brute-force, or enumerate against a target.

The requests it makes to a target are ordinary HTTPS GETs of documents that site serves to any browser: the site root, `/favicon.ico`, `/robots.txt`, `/ads.txt`, and `/.well-known/security.txt`. Every one of those is a documented public-metadata convention that the operator publishes deliberately. Nothing probes for a path the operator meant to hide — there is no request for `/.git/HEAD`, no `/.env`, no directory guessing. Subdomain and DKIM enumeration resolve **DNS names**, which is a query to a public resolver rather than a packet to the target at all.

Search pivots are **constructed, not followed** — the tool builds the query URL and the human decides whether to open it. Nothing is requested from a third party on the user's behalf in a way that would attribute the lookup to them.

Use it on infrastructure you own or are authorised to assess. Geolocation, allocation areas and carrier records describe *infrastructure and number ranges*, not people, and the UI says so wherever it would otherwise be misread.

Two of these lookups can touch individuals rather than infrastructure, and both are deliberately constrained. The **email** module reads only what an address's owner chose to publish — a Gravatar profile they created, a public GitHub profile field they filled in — and never contacts the mailbox. The **username** module reports account existence and self-reported profile text from public APIs, and states plainly, in the output, that a handle is not a person: the same string on two platforms is frequently two different people, which the correlation view is built to show rather than hide.

---

## Licence

MIT.
