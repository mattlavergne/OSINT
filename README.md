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

### IP
- Geolocation **with a precision label** (city / region / country) so coordinates are not mistaken for an address
- RDAP: netblock, CIDR, allocation type, registry, registrant, abuse contact and phone
- Reverse DNS (PTR)
- Shodan **InternetDB** (free, keyless): open ports, known CVEs, observed hostnames, software CPEs
- Hosting/CDN detection, which reframes what the geolocation actually means
- Non-routable input (RFC 1918, loopback, CGNAT, link-local) short-circuits with an explanation instead of four upstream errors

---

## Data sources

Every source below is free and **needs no API key**.

| Source | Used for |
|---|---|
| [ipwho.is](https://ipwho.is) | IP geolocation, ASN, ISP |
| [rdap.org](https://rdap.org) | Domain and IP registration (RDAP bootstrap) |
| [Cloudflare DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) / [Google DoH](https://developers.google.com/speed/public-dns/docs/doh) | All DNS resolution |
| [Shodan InternetDB](https://internetdb.shodan.io) | Open ports, CVEs, hostnames |
| [Cert Spotter](https://sslmate.com/ct_search_api/) | Certificate Transparency (fast) |
| [crt.sh](https://crt.sh) | Certificate Transparency (deep history) |
| [HackerTarget](https://hackertarget.com/) | Passive DNS host search |
| libphonenumber | Phone validation, geocoding, carrier, timezones |

### Optional enrichment

Three keys unlock extra panels. All are optional; nothing breaks without them.

```sh
npx wrangler secret put SHODAN_API_KEY       # deeper host detail
npx wrangler secret put VIRUSTOTAL_API_KEY   # vendor reputation for domains and IPs
npx wrangler secret put ABUSEIPDB_API_KEY    # abuse confidence score for IPs
```

For the Node server, set them as environment variables instead. See `.dev.vars.example`.

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

## Deploying to `mattlavergne.com/OSINT`

Everything below runs on the **Cloudflare free plan**. No paid features are involved.

The app deploys as a **single Worker** that serves the frontend from static assets *and* runs the API. There is no Pages project and no proxy Worker — one deploy, one moving part.

The zone already has `trafficmap-proxy` on `mattlavergne.com/*`, which is why every path currently returns the mattOS shell. Cloudflare resolves overlapping Worker routes by specificity, so `mattlavergne.com/OSINT*` wins for that path while `trafficmap-proxy` keeps serving everything else, unmodified.

### Option A — dashboard (Workers Builds)

**Workers & Pages → Create → Workers → Import a repository**, and pick this repo.

| Field | Value |
|---|---|
| Worker name | `osint` |
| Build command | `npm run build` |
| Deploy command | `npx wrangler deploy` |
| Path | `/` (the project is at the repo root) |

The build command is required — the ~8 MB of phone reference data under `public/data/phone/` is generated, not committed.

`wrangler.toml` already carries the route, so the Worker attaches to `mattlavergne.com/OSINT*` on first deploy. Nothing to configure by hand.

### Option B — CLI

```sh
npm install
npm run deploy      # builds the reference data, then `wrangler deploy`
```

### Verify

```sh
curl -sI https://mattlavergne.com/OSINT           # 301 -> /OSINT/
curl -sS https://mattlavergne.com/OSINT/api/health
```

### How the mount works

The Worker is bound to a path, not a hostname, so requests arrive with `/OSINT` still attached. `src/worker.js` strips it before dispatch, which keeps routing identical to a root-mounted deployment, and redirects bare `/OSINT` to `/OSINT/` — without that trailing slash the browser resolves the app's relative asset and API URLs against the site root and nothing loads.

The strip is conditional, so the same build also works unprefixed on a `*.workers.dev` subdomain if you want to test before attaching the route. To mount somewhere else, change `PREFIX` in `src/worker.js` and the route in `wrangler.toml`; set `PREFIX` to `''` for a root-mounted deploy.

### Free-plan limits worth knowing

| Limit | Free plan | What this app uses |
|---|---|---|
| Worker requests | 100,000/day | one per lookup, plus one per static asset |
| Subrequests per request | 50 | measured 4 (IP), 25 (domain, worst case), 0 (phone) |
| CPU time per request | 10 ms | lookups are I/O-bound, not CPU-bound |
| Static asset requests | free, not billed as requests | — |
| Worker bundle size | 3 MB compressed | code only; the ~8 MB of phone data is assets, not bundle |

The subrequest ceiling is the one to watch: a domain lookup with several resolved addresses measured 25, and redirect hops plus DoH fallbacks push that higher. If you ever see `Too many subrequests`, lower the address-enrichment cap in `src/lookups/domain.js` (`.slice(0, 4)`) to `2`.

### Alternative: a subdomain instead of a path

If you would rather not share the apex with the existing Worker, delete the `routes` block in `wrangler.toml`, deploy, and add `osint.mattlavergne.com` as a **Custom Domain** on the Worker. Cloudflare creates the DNS record and certificate. Then set `PREFIX = ''` in `src/worker.js`, since there is no longer a path prefix to strip.

### Alternative: Node behind nginx

If you move off Cloudflare later:

```sh
BASE_PATH=/OSINT PORT=8787 node server/index.mjs
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

---

## Scope and ethics

Everything here reads public registries, public DNS and public certificate logs. The tool does not scan, brute-force, or enumerate against a target. The single packet it sends to a target is one ordinary HTTPS GET of the site root, to read response headers.

Search pivots are **constructed, not followed** — the tool builds the query URL and the human decides whether to open it. Nothing is requested from a third party on the user's behalf in a way that would attribute the lookup to them.

Use it on infrastructure you own or are authorised to assess. Geolocation, allocation areas and carrier records describe *infrastructure and number ranges*, not people, and the UI says so wherever it would otherwise be misread.

---

## Licence

MIT.
