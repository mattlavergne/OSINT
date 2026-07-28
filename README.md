# GhostTrace

A passive OSINT reconnaissance console for **phone numbers**, **domains** and **IP addresses**, with a web interface.

It is a modern rebuild of the ideas in [GhostTrack](https://github.com/HunxByts/GhostTrack), which was last updated in 2022. GhostTrack was a Python CLI that printed three lookups to a terminal; GhostTrace keeps the premise — cheap, keyless, public-source reconnaissance — and rebuilds it as a deployable web app with a real API, honest data provenance, and sources that still exist.

---

## What changed from GhostTrack

| | GhostTrack (2022) | GhostTrace |
|---|---|---|
| Interface | Python CLI, ANSI art | Web app + JSON API |
| Modules | IP, phone, username | IP, phone, **domain** |
| IP data | `ipwho.is` geolocation only | Geolocation + RDAP netblock owner + abuse contact + reverse DNS + open ports + known CVEs |
| Phone data | `phonenumbers` parse | libphonenumber validation + line type + allocation area + carrier + timezones + local time |
| WHOIS | none | RDAP (the structured IETF replacement for port-43 WHOIS) |
| Username module | 25 hardcoded sites, checked by HTTP 200 | **Removed** — see below |
| Failure mode | one dead API kills the run | per-source isolation; a dead source is reported, the rest still render |
| Data honesty | coordinates printed as fact | precision labelled, portability and allocation caveats stated inline |

**Why the username module is gone.** It worked by requesting 25 profile URLs and treating HTTP 200 as "account exists". That approach produces false positives on every site that returns 200 for missing profiles (most of them, by 2026), false negatives on every site behind Cloudflare or a login wall, and it sends traffic to third parties on the user's behalf. A domain module replaces it: it answers real questions, and every source is a public log rather than a probe. If you want username enumeration, [Sherlock](https://github.com/sherlock-project/sherlock) maintains that problem properly.

---

## The three lookups

### Phone
Google's libphonenumber rules via `libphonenumber-js`, plus the geocoding, carrier and timezone datasets.

- Validity and possibility, distinguished — a plausible length is not an allocated range
- Line type: mobile, fixed line, VoIP, toll-free, premium rate, pager, …
- Geographic area the range is allocated to, and the carrier it was originally allocated to
- Every timezone the number could sit in, with current local time
- E.164 / international / national / RFC 3966 formats
- Search pivots (Google, Truecaller, WhatsApp, Telegram) — links are *built*, never followed
- Optional CNAM caller-ID name and post-portability carrier via Twilio (see below)

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

### IP
- Geolocation **with a precision label** (city / region / country) so coordinates are not mistaken for an address
- RDAP: netblock, CIDR, allocation type, registry, registrant, abuse contact and phone
- Reverse DNS (PTR)
- Shodan **InternetDB** (free, keyless): open ports, known CVEs, observed hostnames, software CPEs
- Hosting/CDN detection, which reframes what the geolocation actually means
- **BGP routing** from RIPEstat: announced prefix, origin AS and holder, announcement status — who announces a prefix is harder to falsify than a geolocation record
- **Co-hosted domains** on the same address, which names the operator on dedicated hosting and flags shared infrastructure when it is not
- Non-routable input (RFC 1918, loopback, CGNAT, link-local) short-circuits with an explanation instead of four upstream errors

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
| [archive.org](https://archive.org/help/wayback_api.php) | First and last archived capture |
| The site's own HTML | Title, org name, copyright entity, contacts, social profiles, analytics IDs |
| `/.well-known/security.txt` | Published security contact (RFC 9116) |
| [OpenStreetMap Overpass](https://overpass-api.de/) | Reverse phone → business/POI name, address and website |
| libphonenumber | Phone validation, geocoding, carrier, timezones |

### Optional enrichment

These unlock extra panels. All are optional; nothing breaks without them.

```sh
npx wrangler secret put SHODAN_API_KEY       # deeper host detail
npx wrangler secret put VIRUSTOTAL_API_KEY   # vendor reputation for domains and IPs
npx wrangler secret put ABUSEIPDB_API_KEY    # abuse confidence score for IPs
npx wrangler secret put TWILIO_ACCOUNT_SID   # CNAM caller-ID name for phone numbers
npx wrangler secret put TWILIO_AUTH_TOKEN
```

For the Node server, set them as environment variables instead. See `.dev.vars.example`.

### On putting a name to a phone number

The answer splits cleanly in two, and it is worth being precise about which half you are in.

**Businesses and public places — yes, free.** GhostTrace reverse-queries **OpenStreetMap** via Overpass. Where a business has been mapped with its phone number, this returns the name, category, brand, street address, website and a link to the OSM record. `+1 212-343-3355` resolves to Hard Rock Cafe, 1501 Broadway, with its website. It is open data (ODbL), keyless, and the operator published the number themselves. Coverage is the limitation, not licensing: it hits for mapped businesses and misses everything else.

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
npm test           # 38 offline tests
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
| Subrequests per request | 50 | measured 6 (IP), 29 (domain, worst case), 0 (phone) |
| CPU time per request | 10 ms | lookups are I/O-bound, not CPU-bound |
| Static asset requests | free, not billed as requests | — |
| Worker bundle size | 3 MB compressed | code only; the ~8 MB of phone data is assets, not bundle |

The subrequest ceiling is the one to watch: a domain lookup with several resolved addresses measured 29, and redirect hops plus DoH fallbacks push that higher. If you ever see `Too many subrequests`, lower the address-enrichment cap in `src/lookups/domain.js` (`.slice(0, 4)`) to `2`.

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
GET /api/domain?q=<domain>
GET /api/ip?q=<address>
GET /api/health
```

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
src/lookups/{ip,domain,phone}.js
src/lib/{http,dns,rdap,validate}.js
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

**Provider chains, because shared egress breaks per-IP quotas.** On Workers the outbound source address is Cloudflare's, shared with every other customer, so any free API that meters per IP is effectively pre-exhausted before your request arrives. In production this showed up as ipwho.is returning 429, HackerTarget reporting its daily quota spent, and rdap.org — itself behind Cloudflare — failing the Worker-to-Cloudflare TLS handshake with 525. Geolocation, reverse-IP and RDAP therefore each run an ordered chain of independent providers and take the first success, and the answering provider is reported in the payload so a degraded result is visible rather than silent. Prefer unmetered infrastructure endpoints (RIPEstat, IANA, DoH resolvers, Shodan InternetDB) over commercial free tiers wherever both will do.

---

## Scope and ethics

Everything here reads public registries, public DNS and public certificate logs. The tool does not scan, brute-force, or enumerate against a target. The single packet it sends to a target is one ordinary HTTPS GET of the site root, to read response headers.

Search pivots are **constructed, not followed** — the tool builds the query URL and the human decides whether to open it. Nothing is requested from a third party on the user's behalf in a way that would attribute the lookup to them.

Use it on infrastructure you own or are authorised to assess. Geolocation, allocation areas and carrier records describe *infrastructure and number ranges*, not people, and the UI says so wherever it would otherwise be misread.

---

## Licence

MIT.
