/**
 * GhostTrace front-end.
 *
 * No framework and no build step — the whole app is one module against the DOM.
 * Everything rendered here comes from third-party registries and DNS records,
 * i.e. attacker-controlled text, so all interpolation goes through the escaping
 * `html` tagged template below. Nothing reaches innerHTML unescaped.
 */

/* ────────────────────────────────────────────── escaping + DOM helpers */

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/** Marks a string as already-safe HTML, exempting it from escaping. */
class Safe {
  constructor(value) { this.value = value; }
  toString() { return this.value; }
}
const raw = (value) => new Safe(value);

function escape(value) {
  if (value instanceof Safe) return value.value;
  if (value == null || value === false) return '';
  if (Array.isArray(value)) return value.map(escape).join('');
  return String(value).replace(/[&<>"']/g, (c) => ESCAPES[c]);
}

/** Tagged template that escapes every interpolation by default. */
function html(strings, ...values) {
  return raw(strings.reduce((out, str, i) => out + str + escape(values[i]), ''));
}

const $ = (selector, scope = document) => scope.querySelector(selector);

/* ────────────────────────────────────────────── configuration */

/**
 * The app is designed to be mounted under a path prefix (mattlavergne.com/OSINT),
 * so the API base is derived from wherever index.html was served rather than
 * assumed to be at the site root.
 */
const BASE = new URL('.', new URL(document.baseURI)).pathname;
const api = (path) => `${BASE}api/${path}`;

const MODES = {
  phone: {
    placeholder: 'Enter a phone number…',
    examples: ['+1 213 373 4253', '+44 20 7123 4567', '+33 6 12 34 56 78', '+91 98765 43210'],
    hasRegion: true,
  },
  domain: {
    placeholder: 'Enter a domain name…',
    examples: ['github.com', 'anthropic.com', 'mattlavergne.com', 'wikipedia.org'],
    hasRegion: false,
  },
  ip: {
    placeholder: 'Enter an IPv4 or IPv6 address…',
    examples: ['8.8.8.8', '1.1.1.1', '140.82.114.3', '2606:4700:4700::1111'],
    hasRegion: false,
  },
};

const HISTORY_KEY = 'ghosttrace.history';
const THEME_KEY = 'ghosttrace.theme';
const MAX_HISTORY = 24;

let mode = 'phone';
let lastResult = null;

/* ────────────────────────────────────────────── theme */

function applyTheme(theme) {
  const resolved =
    theme === 'auto'
      ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : theme;
  document.documentElement.dataset.theme = resolved;
  $('#metaTheme').content = resolved === 'dark' ? '#070b16' : '#e9edf5';
}

function initTheme() {
  const stored = localStorage.getItem(THEME_KEY) ?? 'auto';
  applyTheme(stored);

  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if ((localStorage.getItem(THEME_KEY) ?? 'auto') === 'auto') applyTheme('auto');
  });

  $('#themeBtn').addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
  });
}

/* ────────────────────────────────────────────── mode switching */

function setMode(next, { focus = true } = {}) {
  mode = next;
  const config = MODES[next];

  document.querySelectorAll('.mode').forEach((button) => {
    button.setAttribute('aria-selected', String(button.dataset.mode === next));
  });

  const index = Object.keys(MODES).indexOf(next);
  $('.mode-glider').style.transform = `translateX(calc(${index} * (100% + 4px)))`;

  const input = $('#query');
  input.placeholder = config.placeholder;
  $('#region').hidden = !config.hasRegion;

  renderExamples(config.examples);
  if (focus) input.focus();
}

function renderExamples(examples) {
  $('#examples').innerHTML = String(html`
    <span>Try:</span>
    ${examples.map((value) => html`<button class="example" type="button" data-value="${value}">${value}</button>`)}
  `);
}

/* ────────────────────────────────────────────── region picker */

async function initRegions() {
  const select = $('#region');
  select.innerHTML = '<option value="">Auto-detect</option>';

  try {
    const index = await fetch(`${BASE}data/phone/index.json`).then((r) => (r.ok ? r.json() : null));
    if (!index?.countries) return;

    const names = new Intl.DisplayNames(['en'], { type: 'region' });
    const options = index.countries
      .map(({ code, callingCode }) => {
        let label = code;
        try { label = names.of(code) ?? code; } catch { /* keep the raw code */ }
        return { code, label, callingCode };
      })
      .sort((a, b) => a.label.localeCompare(b.label));

    select.insertAdjacentHTML(
      'beforeend',
      String(html`${options.map((o) => html`<option value="${o.code}">${o.label} (${o.callingCode})</option>`)}`),
    );
  } catch {
    // The picker is an aid, not a requirement — E.164 input needs no region.
  }
}

/* ────────────────────────────────────────────── lookup */

async function runLookup(value, region) {
  const results = $('#results');
  const button = $('#runBtn');

  $('#intro').hidden = true;
  button.classList.add('busy');
  button.disabled = true;
  results.innerHTML = String(html`
    <div class="glass skeleton">
      <div class="bar w38"></div>
      <div class="bar w82"></div>
      <div class="bar w64"></div>
      <div class="bar w73"></div>
    </div>
  `);

  const params = new URLSearchParams({ q: value });
  if (region) params.set('region', region);

  try {
    const response = await fetch(`${api(mode)}?${params}`, { headers: { accept: 'application/json' } });
    const body = await response.json();

    if (!response.ok) {
      renderError(body.error ?? 'Lookup failed', body.detail ?? `HTTP ${response.status}`);
      return;
    }

    lastResult = body;
    render(body);
    pushHistory(mode, value, region);
    syncUrl(mode, value, region);
  } catch (err) {
    renderError('Could not reach the API', err.message);
  } finally {
    button.classList.remove('busy');
    button.disabled = false;
  }
}

function renderError(title, detail) {
  $('#results').innerHTML = String(html`
    <div class="glass error">
      <h2>${title}</h2>
      <p>${detail}</p>
    </div>
  `);
}

/* ────────────────────────────────────────────── rendering */

const ICON_COPY = raw('<svg viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg>');
const ICON_EXTERNAL = raw('<svg viewBox="0 0 24 24"><path d="M14 4h6v6M20 4l-8 8M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></svg>');

function render(data) {
  const renderer = { phone: renderPhone, domain: renderDomain, ip: renderIp }[data.query.type];

  // Every fragment below is a `Safe`, so interpolating them nests without
  // double-escaping; `String()` unwraps the final result for innerHTML.
  $('#results').innerHTML = String(html`
    ${resultHeader(data)}
    ${renderer(data)}
    ${sourcesCard(data.sources)}
    <details class="glass raw">
      <summary>Raw JSON</summary>
      <pre>${JSON.stringify(data, null, 2)}</pre>
    </details>
  `);
}

function resultHeader(data) {
  const subtitle = {
    phone: () => [data.formats?.international, data.numberTypeLabel, data.country].filter(Boolean).join(' · '),
    domain: () => [data.query.isSubdomain ? `subdomain of ${data.query.apex}` : 'apex domain',
                   data.registration?.registrar].filter(Boolean).join(' · '),
    ip: () => [`IPv${data.query.version}`, data.geolocation?.organization, data.registry?.name].filter(Boolean).join(' · '),
  }[data.query.type]();

  const title = data.query.type === 'phone' ? (data.formats?.e164 ?? data.query.value) : data.query.value;

  return html`
    <div class="glass">
      <div class="result-head">
        <div class="result-title">
          <h2>${title}</h2>
          <p>${subtitle || '—'}${data.elapsedMs ? ` · ${data.elapsedMs} ms` : ''}</p>
        </div>
        <div class="result-actions">
          <button class="action" data-act="copy">${ICON_COPY} Copy JSON</button>
          <button class="action" data-act="json">Download JSON</button>
          <button class="action" data-act="md">Download report</button>
        </div>
      </div>
      ${findings(data.assessment)}
    </div>
  `;
}

function findings(list = []) {
  if (!list.length) return raw('');
  return html`
    <div class="findings">
      ${list.map((f) => html`
        <div class="finding ${f.level}">
          <span class="dot"></span>
          <div><h4>${f.title}</h4><p>${f.detail}</p></div>
        </div>
      `)}
    </div>
  `;
}

/** A definition list, skipping rows whose value is empty. */
function dl(rows) {
  const present = rows.filter(([, value]) => value != null && value !== '' && !(Array.isArray(value) && !value.length));
  if (!present.length) return html`<p class="muted">No data available.</p>`;
  return html`<dl>${present.map(([label, value]) => html`<dt>${label}</dt><dd>${value}</dd>`)}</dl>`;
}

function card(title, body, { wide = false, count = null } = {}) {
  if (body == null) return raw('');
  return html`
    <div class="glass card${wide ? ' wide' : ''}">
      <h3>${title}${count != null ? html`<span class="count">${count}</span>` : ''}</h3>
      ${body}
    </div>
  `;
}

function pivotsCard(pivots = []) {
  if (!pivots.length) return raw('');
  return card('Pivot to', html`
    <div class="pivots">
      ${pivots.map((p) => html`<a class="pivot" href="${p.url}" target="_blank" rel="noopener noreferrer">${p.label}${ICON_EXTERNAL}</a>`)}
    </div>
  `, { wide: true });
}

function sourcesCard(sources = {}) {
  const entries = Object.entries(sources);
  if (!entries.length) return raw('');
  return html`
    <div class="glass card">
      <h3>Sources</h3>
      <div class="sources">
        ${entries.map(([name, state]) => html`
          <span class="source${state.ok ? '' : ' failed'}" title="${state.error ?? 'OK'}">
            <span class="dot"></span>${name}${state.ok ? '' : ' — unavailable'}
          </span>
        `)}
      </div>
    </div>
  `;
}

/* ─────────────────────────────── phone */

function renderPhone(d) {
  return html`
    <div class="cards">
      ${card('Number', dl([
        ['Status', d.valid ? html`<span class="pill good">Valid</span>` : html`<span class="pill bad">Invalid</span>`],
        ['Type', d.numberTypeLabel],
        ['Country', d.country ? `${d.country} (${d.countryCallingCode})` : d.countryCallingCode],
        ['National', html`<span class="mono">${d.nationalNumber}</span>`],
        ['Allocated area', d.location],
        ['Carrier', d.carrier],
      ]))}

      ${card('Formats', dl([
        ['E.164', html`<span class="mono">${d.formats.e164}</span>`],
        ['International', html`<span class="mono">${d.formats.international}</span>`],
        ['National', html`<span class="mono">${d.formats.national}</span>`],
        ['RFC 3966', html`<span class="mono">${d.formats.rfc3966}</span>`],
        ['Example for region', d.example ? html`<span class="mono muted">${d.example}</span>` : null],
      ]))}

      ${d.places?.length ? card('Matched in OpenStreetMap', html`
        ${d.places.map((pl) => html`
          <h4 class="rrtype">${pl.name}${pl.category ? html` <span class="pill">${pl.category}</span>` : ''}</h4>
          ${dl([
            ['Brand', pl.brand],
            ['Operator', pl.operator],
            ['Address', pl.address],
            ['Website', pl.website ? html`<a href="${pl.website}" target="_blank" rel="noopener noreferrer">${pl.website}</a>` : null],
            ['Listed number', html`<span class="mono">${pl.phone}</span>`],
            ['OSM record', html`<a href="${pl.osmUrl}" target="_blank" rel="noopener noreferrer">view</a>`],
          ])}
        `)}
        <p class="note">
          Community-contributed open data. It covers mapped businesses and public places only —
          never individuals — and may be out of date or refer to a previous occupant.
        </p>
      `, { wide: true, count: d.places.length }) : raw('')}

      ${d.identity ? card('Caller identity', dl([
        ['Caller name', d.identity.callerName
          ? html`<strong>${d.identity.callerName}</strong>` : html`<span class="muted">no CNAM listing</span>`],
        ['Listing type', d.identity.callerType],
        ['Current carrier', d.identity.currentCarrier],
        ['Current line type', d.identity.currentLineType],
        ['MCC / MNC', d.identity.mobileCountryCode
          ? `${d.identity.mobileCountryCode} / ${d.identity.mobileNetworkCode}` : null],
      ])) : raw('')}

      ${d.localTime?.length ? card('Local time', html`
        <ul class="record-list">
          ${d.localTime.map((t) => html`<li>${t.zone} — ${t.time ?? 'unknown'}</li>`)}
        </ul>
      `, { count: d.timezones.length }) : raw('')}

      ${d.caveats?.length ? card('Read this before acting on it', html`
        <ul class="caveats">${d.caveats.map((c) => html`<li>${c}</li>`)}</ul>
      `, { wide: true }) : raw('')}

      ${pivotsCard(d.pivots)}
    </div>
  `;
}

/* ─────────────────────────────── ip */

function renderIp(d) {
  if (!d.routable) {
    return html`<div class="cards">${card('Not routable', html`<p class="muted">${d.summary}</p>`, { wide: true })}</div>`;
  }

  const geo = d.geolocation;
  const reg = d.registry;
  const exp = d.exposure;

  return html`
    <div class="cards">
      ${geo ? card('Geolocation', dl([
        ['Country', geo.flag ? `${geo.flag} ${geo.country}` : geo.country],
        ['Region', geo.region],
        ['City', geo.city],
        ['Postal', geo.postal],
        ['Precision', html`<span class="pill warn">${geo.precision}-level</span>`],
        ['Timezone', geo.timezone ? `${geo.timezone.id} (UTC${geo.timezone.utcOffset})` : null],
        ['Coordinates', geo.mapUrl
          ? html`<a href="${geo.mapUrl}" target="_blank" rel="noopener noreferrer">${geo.latitude}, ${geo.longitude}</a>`
          : null],
      ])) : raw('')}

      ${card('Network', dl([
        ['Organisation', geo?.organization],
        ['ISP', geo?.isp],
        ['ASN', geo?.asn],
        ['Reverse DNS', d.reverseDns ? html`<span class="mono">${d.reverseDns}</span>` : html`<span class="muted">none published</span>`],
        ['Netblock', reg?.cidr ?? reg?.range],
        ['Allocation', reg?.type],
        ['Registry', reg?.registry],
      ]))}

      ${reg ? card('Registry record', dl([
        ['Handle', reg.handle],
        ['Name', reg.name],
        ['Registrant', reg.registrant?.name ?? reg.registrant?.organization],
        ['Registered', formatDate(reg.registered)],
        ['Updated', formatDate(reg.updated)],
        ['Abuse contact', reg.abuseContact?.email
          ? html`<a href="mailto:${reg.abuseContact.email}">${reg.abuseContact.email}</a>`
          : null],
        ['Abuse phone', reg.abuseContact?.phone],
      ])) : raw('')}

      ${exp ? card('Exposure', exp.seen ? html`
        ${dl([
          ['Open ports', exp.ports.length
            ? html`<div class="tags">${exp.ports.map((p) => html`<span class="tag${isRiskyPort(p) ? ' warn' : ''}">${p}</span>`)}</div>`
            : html`<span class="muted">none observed</span>`],
          ['Known CVEs', exp.vulnerabilities.length
            ? html`<div class="tags">${exp.vulnerabilities.map((v) => html`<span class="tag bad">${v}</span>`)}</div>`
            : html`<span class="pill good">none</span>`],
          ['Hostnames', exp.hostnames.length ? html`<span class="mono">${exp.hostnames.join(', ')}</span>` : null],
          ['Software', exp.software.length ? html`<span class="mono">${exp.software.join(', ')}</span>` : null],
          ['Tags', exp.tags.length ? html`<div class="tags">${exp.tags.map((t) => html`<span class="tag">${t}</span>`)}</div>` : null],
        ])}
      ` : html`<p class="muted">Shodan has never observed this address. That usually means nothing is listening on a scanned port.</p>`,
        { count: exp.seen ? exp.ports.length : null }) : raw('')}

      ${d.routing ? card('BGP routing', dl([
        ['Announced prefix', d.routing.announcedPrefix ? html`<span class="mono">${d.routing.announcedPrefix}</span>` : null],
        ['Currently announced', d.routing.announced === true ? html`<span class="pill good">yes</span>`
          : d.routing.announced === false ? html`<span class="pill warn">no</span>` : null],
        ['Origin AS', d.routing.originAsns?.length
          ? html`${d.routing.originAsns.map((a) => html`<span class="mono">${a.asn}</span>${a.holder ? ` — ${a.holder}` : ''}`)}`
          : null],
        ['Registry block', d.routing.blockDescription],
        ['Covering prefix', d.routing.relatedPrefixes?.length
          ? html`<span class="mono">${d.routing.relatedPrefixes.join(', ')}</span>` : null],
      ])) : raw('')}

      ${d.hostedDomains ? card('Domains on this address', d.hostedDomains.count ? html`
        <div class="scroll">
          <ul class="record-list">${d.hostedDomains.domains.map((n) => html`<li>${n}</li>`)}</ul>
        </div>
        <p class="note">
          ${d.hostedDomains.shared
            ? 'Shared hosting or a CDN front — this address does not identify a single owner.'
            : 'Few names resolve here, which suggests dedicated hosting.'}
          ${d.hostedDomains.truncated ? ' Showing the first 100.' : ''}
        </p>
      ` : html`<p class="muted">No domains found resolving to this address.</p>`,
        { wide: d.hostedDomains.count > 12, count: d.hostedDomains.count }) : raw('')}

      ${d.abuse ? card('Abuse reports', dl([
        ['Confidence', html`<span class="pill ${d.abuse.confidenceScore >= 50 ? 'bad' : d.abuse.confidenceScore > 0 ? 'warn' : 'good'}">${d.abuse.confidenceScore}%</span>`],
        ['Reports (90d)', d.abuse.totalReports],
        ['Distinct reporters', d.abuse.distinctReporters],
        ['Last reported', formatDate(d.abuse.lastReportedAt)],
        ['Usage type', d.abuse.usageType],
        ['Tor exit node', d.abuse.isTor === true ? 'yes' : d.abuse.isTor === false ? 'no' : null],
      ])) : raw('')}

      ${d.reputation ? card('Vendor reputation', dl([
        ['Malicious', d.reputation.malicious],
        ['Suspicious', d.reputation.suspicious],
        ['Harmless', d.reputation.harmless],
        ['Score', d.reputation.reputation],
      ])) : raw('')}

      ${pivotsCard(d.pivots)}
    </div>
  `;
}

const RISKY_PORTS = new Set([21, 23, 135, 445, 3306, 3389, 5432, 5900, 6379, 9200, 27017]);
const isRiskyPort = (port) => RISKY_PORTS.has(port);

/* ─────────────────────────────── domain */

function renderDomain(d) {
  const reg = d.registration;
  const email = d.email;
  const dns = d.dns ?? {};

  const id = d.identity;

  return html`
    <div class="cards">
      ${id && (id.names.length || id.contacts.length || id.socialProfiles.length) ? card('Attribution', html`
        ${id.names.length ? html`
          <h4 class="rrtype">Candidate names</h4>
          <ul class="record-list">
            ${id.names.map((n) => html`<li>${n.value} <span class="pill ${n.confidence === 'high' ? 'good' : n.confidence === 'low' ? 'warn' : ''}">${n.confidence}</span> <span class="muted">${n.source}</span></li>`)}
          </ul>` : html`<p class="note">No organisation name is published. Registrant is ${id.registrantStatus}.</p>`}

        ${id.contacts.length ? html`
          <h4 class="rrtype">Contacts</h4>
          <ul class="record-list">
            ${id.contacts.map((c) => html`<li>${c.value} <span class="muted">${c.source}</span></li>`)}
          </ul>` : ''}

        ${id.socialProfiles.length ? html`
          <h4 class="rrtype">Linked profiles</h4>
          <div class="pivots">
            ${id.socialProfiles.map((u) => html`<a class="pivot" href="${u}" target="_blank" rel="noopener noreferrer">${u.replace(/^https:\/\//, '')}${ICON_EXTERNAL}</a>`)}
          </div>` : ''}

        ${id.trackingIds.length ? html`
          <h4 class="rrtype">Analytics IDs</h4>
          <ul class="record-list">
            ${id.trackingIds.map((t) => html`<li>${t.id} <span class="muted">${t.type}</span></li>`)}
          </ul>
          <p class="note">The same ID on another site indicates a shared operator. Searchable on publicwww.com and analyzeid.com.</p>` : ''}
      `, { wide: true }) : raw('')}

      ${d.page ? card('Site', dl([
        ['Title', d.page.title],
        ['Description', d.page.description],
        ['Site name', d.page.siteName],
        ['Author', d.page.author],
        ['Generator', d.page.generator ? html`<span class="pill">${d.page.generator}</span>` : null],
        ['Language', d.page.language],
      ])) : raw('')}

      ${d.archive?.archived ? card('Archive history', dl([
        ['First archived', d.archive.firstSnapshotUrl
          ? html`<a href="${d.archive.firstSnapshotUrl}" target="_blank" rel="noopener noreferrer">${d.archive.firstSeen}</a>`
          : d.archive.firstSeen],
        ['Last archived', d.archive.lastSeen],
        ['All captures', html`<a href="${d.archive.url}" target="_blank" rel="noopener noreferrer">Wayback Machine</a>`],
      ])) : raw('')}

      ${d.securityTxt ? card('security.txt', dl([
        ['Contact', d.securityTxt.contacts.join(', ')],
        ['Policy', d.securityTxt.policy],
        ['Expires', formatDate(d.securityTxt.expires)],
        ['Acknowledgments', d.securityTxt.acknowledgments],
        ['Hiring', d.securityTxt.hiring],
      ])) : raw('')}

      ${reg ? card('Registration', dl([
        ['Registrar', reg.registrar],
        ['IANA ID', reg.registrarIana],
        ['Created', formatDate(reg.created)],
        ['Updated', formatDate(reg.updated)],
        ['Expires', reg.expires
          ? html`${formatDate(reg.expires)} ${reg.daysUntilExpiry != null
              ? html`<span class="pill ${reg.daysUntilExpiry < 30 ? 'warn' : ''}">${reg.daysUntilExpiry}d</span>` : ''}`
          : null],
        ['Age', reg.ageDays != null ? `${reg.ageDays.toLocaleString()} days (${(reg.ageDays / 365).toFixed(1)} years)` : null],
        ['DNSSEC', reg.dnssec === true ? html`<span class="pill good">signed</span>`
                  : reg.dnssec === false ? html`<span class="pill">unsigned</span>` : null],
        ['Registrant', reg.registrant
          ? (reg.registrant.redacted
              ? html`<span class="muted">redacted for privacy</span>`
              : (reg.registrant.organization ?? reg.registrant.name))
          : html`<span class="muted">not published</span>`],
        ['Abuse contact', reg.abuseContact?.email
          ? html`<a href="mailto:${reg.abuseContact.email}">${reg.abuseContact.email}</a>` : null],
      ])) : raw('')}

      ${reg?.status?.length ? card('Registry status', html`
        <ul class="record-list">
          ${reg.status.map((s) => html`<li>${s.code}${s.note ? html` — ${s.note}` : ''}</li>`)}
        </ul>
      `, { count: reg.status.length }) : raw('')}

      ${card('DNS records', html`
        <div class="scroll">
          ${['A', 'AAAA', 'MX', 'NS', 'SOA', 'CAA'].map((type) => {
            const set = dns[type];
            if (!set?.records?.length) return raw('');
            return html`
              <h4 class="rrtype">${type} · TTL ${set.ttl ?? '—'}</h4>
              <ul class="record-list">${set.records.map((r) => html`<li>${r}</li>`)}</ul>
            `;
          })}
        </div>
      `, { wide: true })}

      ${email ? card('Email authentication', dl([
        ['SPF', email.spf
          ? html`<span class="pill ${email.spf.qualifier === '+' ? 'bad' : email.spf.qualifier === '-' ? 'good' : 'warn'}">${email.spf.policy}</span>
                 <span class="muted"> · ${email.spf.lookupCount} lookups</span>`
          : html`<span class="pill bad">absent</span>`],
        ['DMARC', email.dmarc
          ? html`<span class="pill ${email.dmarc.enforcing ? 'good' : 'warn'}">p=${email.dmarc.policy}</span>
                 ${email.dmarc.subdomainPolicy ? html`<span class="muted"> · sp=${email.dmarc.subdomainPolicy}</span>` : ''}`
          : html`<span class="pill bad">absent</span>`],
        ['DMARC reports', email.dmarc?.aggregateReports],
        ['MTA-STS', email.mtaSts ? html`<span class="pill good">present</span>` : html`<span class="pill">absent</span>`],
        ['BIMI', email.bimi ? html`<span class="pill good">present</span>` : null],
        ['MX', dns.MX?.records?.length ? html`<span class="mono">${dns.MX.records.join(', ')}</span>` : html`<span class="muted">no mail servers</span>`],
      ])) : raw('')}

      ${email?.spf ? card('SPF detail', html`
        <p class="rawvalue">${email.spf.record}</p>
        ${email.spf.includes.length ? html`<div class="tags spaced">${email.spf.includes.map((i) => html`<span class="tag">${i}</span>`)}</div>` : ''}
      `) : raw('')}

      ${d.hosting?.length ? card('Hosting', html`
        <div class="scroll"><table>
          <thead><tr><th>Address</th><th>Location</th><th>Organisation</th><th>Ports</th></tr></thead>
          <tbody>${d.hosting.map((h) => html`
            <tr>
              <td class="mono">${h.address}</td>
              <td>${h.flag ?? ''} ${[h.city, h.country].filter(Boolean).join(', ') || '—'}</td>
              <td>${h.organization ?? '—'}${h.asn ? html` <span class="muted">${h.asn}</span>` : ''}</td>
              <td class="mono">${h.ports.length ? h.ports.join(', ') : '—'}</td>
            </tr>
          `)}</tbody>
        </table></div>
      `, { wide: true, count: d.hosting.length }) : raw('')}

      ${d.subdomains?.length ? card('Subdomains', html`
        <div class="scroll">
          <ul class="record-list">${d.subdomains.map((s) => html`<li>${s}</li>`)}</ul>
        </div>
        ${d.certificates?.discoverySources?.length ? html`
          <p class="note">
            From ${d.certificates.discoverySources.map((s) => `${s.name} (${s.found})`).join(', ')}.
            Names appear in public logs; some may no longer resolve.
          </p>` : ''}
      `, { wide: true, count: d.subdomains.length }) : raw('')}

      ${d.certificates?.recentCertificates?.length ? card('Recent certificates', html`
        <div class="scroll"><table>
          <thead><tr><th>Name</th><th>Issuer</th><th>Valid from</th><th>Expires</th></tr></thead>
          <tbody>${d.certificates.recentCertificates.map((c) => html`
            <tr>
              <td class="mono">${c.commonName ?? '—'}</td>
              <td>${c.issuer ?? '—'}</td>
              <td>${formatDate(c.validFrom)}</td>
              <td>${formatDate(c.validTo)}</td>
            </tr>
          `)}</tbody>
        </table></div>
      `, { wide: true, count: d.certificates.totalCertificates }) : raw('')}

      ${d.httpHeaders ? card('HTTP response', dl([
        ['Status', d.httpHeaders.status],
        ['Final URL', d.httpHeaders.finalUrl],
        ['Server', d.httpHeaders.server],
        ['CDN', d.httpHeaders.cdn],
        ['X-Powered-By', d.httpHeaders.poweredBy ? html`<span class="pill warn">${d.httpHeaders.poweredBy}</span>` : null],
        ['HSTS', d.httpHeaders.strictTransportSecurity
          ? html`<span class="pill good">on</span>` : html`<span class="pill warn">off</span>`],
        ['CSP', d.httpHeaders.contentSecurityPolicy
          ? html`<span class="pill good">present</span>` : html`<span class="pill warn">absent</span>`],
        ['X-Frame-Options', d.httpHeaders.xFrameOptions],
        ['Referrer-Policy', d.httpHeaders.referrerPolicy],
      ])) : raw('')}

      ${email?.verifications?.length ? card('Service verifications', html`
        <div class="scroll"><ul class="record-list">${email.verifications.map((v) => html`<li>${v}</li>`)}</ul></div>
        <p class="note">
          Domain-verification TXT records reveal which SaaS platforms the organisation uses.
        </p>
      `, { wide: true, count: email.verifications.length }) : raw('')}

      ${d.reputation ? card('Vendor reputation', dl([
        ['Malicious', d.reputation.malicious],
        ['Suspicious', d.reputation.suspicious],
        ['Harmless', d.reputation.harmless],
      ])) : raw('')}

      ${pivotsCard(d.pivots)}
    </div>
  `;
}

/* ────────────────────────────────────────────── exports */

function onResultAction(event) {
  const button = event.target.closest('[data-act]');
  if (!button || !lastResult) return;

  const stamp = new Date().toISOString().slice(0, 10);
  const slug = String(lastResult.query.value).replace(/[^a-z0-9.+-]/gi, '_');

  if (button.dataset.act === 'copy') {
    navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2))
      .then(() => toast('Copied to clipboard'))
      .catch(() => toast('Clipboard unavailable'));
  } else if (button.dataset.act === 'json') {
    download(`ghosttrace-${slug}-${stamp}.json`, JSON.stringify(lastResult, null, 2), 'application/json');
  } else if (button.dataset.act === 'md') {
    download(`ghosttrace-${slug}-${stamp}.md`, toMarkdown(lastResult), 'text/markdown');
  }
}

function download(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = Object.assign(document.createElement('a'), { href: url, download: filename });
  link.click();
  URL.revokeObjectURL(url);
  toast(`Saved ${filename}`);
}

/** A plain-text report, for pasting into a ticket or case note. */
function toMarkdown(d) {
  const lines = [
    `# GhostTrace report — ${d.query.value}`,
    '',
    `- **Type:** ${d.query.type}`,
    `- **Generated:** ${new Date().toISOString()}`,
    '',
    '## Findings',
    '',
    ...(d.assessment ?? []).map((f) => `- **[${f.level.toUpperCase()}] ${f.title}** — ${f.detail}`),
    '',
  ];

  const section = (title, rows) => {
    const present = rows.filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && !v.length));
    if (!present.length) return;
    lines.push(`## ${title}`, '');
    present.forEach(([label, value]) => {
      lines.push(`- **${label}:** ${Array.isArray(value) ? value.join(', ') : value}`);
    });
    lines.push('');
  };

  if (d.query.type === 'phone') {
    section('Number', [
      ['Valid', d.valid], ['Type', d.numberTypeLabel], ['Country', d.country],
      ['E.164', d.formats?.e164], ['Allocated area', d.location], ['Carrier', d.carrier],
      ['Timezones', d.timezones],
    ]);
    if (d.places?.length) {
      lines.push('## OpenStreetMap matches', '',
        ...d.places.map((pl) => `- **${pl.name}**${pl.category ? ` (${pl.category})` : ''}${pl.address ? ` — ${pl.address}` : ''}${pl.website ? ` — ${pl.website}` : ''}`), '');
    }
    section('Caller identity (CNAM)', [
      ['Caller name', d.identity?.callerName], ['Listing type', d.identity?.callerType],
      ['Current carrier', d.identity?.currentCarrier], ['Current line type', d.identity?.currentLineType],
    ]);
    if (d.caveats?.length) {
      lines.push('## Caveats', '', ...d.caveats.map((c) => `- ${c}`), '');
    }
  } else if (d.query.type === 'ip') {
    section('Geolocation', [
      ['Country', d.geolocation?.country], ['Region', d.geolocation?.region], ['City', d.geolocation?.city],
      ['Precision', d.geolocation?.precision], ['Coordinates', d.geolocation?.latitude != null
        ? `${d.geolocation.latitude}, ${d.geolocation.longitude}` : null],
    ]);
    section('Network', [
      ['Organisation', d.geolocation?.organization], ['ASN', d.geolocation?.asn],
      ['Reverse DNS', d.reverseDns], ['Netblock', d.registry?.cidr ?? d.registry?.range],
      ['Abuse contact', d.registry?.abuseContact?.email],
      ['Announced prefix', d.routing?.announcedPrefix],
      ['Origin AS', d.routing?.originAsns?.map((a) => `${a.asn}${a.holder ? ` (${a.holder})` : ''}`)],
    ]);
    if (d.hostedDomains?.count) {
      lines.push(`## Domains on this address (${d.hostedDomains.count})`, '',
        ...d.hostedDomains.domains.map((n) => `- ${n}`), '');
    }
    section('Exposure', [
      ['Open ports', d.exposure?.ports], ['Known CVEs', d.exposure?.vulnerabilities],
      ['Hostnames', d.exposure?.hostnames],
    ]);
  } else {
    section('Attribution', [
      ['Candidate names', d.identity?.names?.map((n) => `${n.value} (${n.source}, ${n.confidence} confidence)`)],
      ['Contacts', d.identity?.contacts?.map((c) => `${c.value} (${c.source})`)],
      ['Linked profiles', d.identity?.socialProfiles],
      ['Analytics IDs', d.identity?.trackingIds?.map((t) => `${t.id} (${t.type})`)],
      ['Registrant status', d.identity?.registrantStatus],
    ]);
    section('Site', [
      ['Title', d.page?.title], ['Description', d.page?.description],
      ['Site name', d.page?.siteName], ['Generator', d.page?.generator],
    ]);
    section('Archive', [
      ['First archived', d.archive?.firstSeen], ['Last archived', d.archive?.lastSeen],
    ]);
    section('Registration', [
      ['Registrar', d.registration?.registrar], ['Created', d.registration?.created],
      ['Expires', d.registration?.expires], ['Age (days)', d.registration?.ageDays],
      ['DNSSEC', d.registration?.dnssec], ['Nameservers', d.registration?.nameservers],
    ]);
    section('Email authentication', [
      ['SPF', d.email?.spf?.record], ['DMARC', d.email?.dmarc?.record],
      ['MTA-STS', d.email?.mtaSts], ['MX', d.dns?.MX?.records],
    ]);
    section('DNS', [
      ['A', d.dns?.A?.records], ['AAAA', d.dns?.AAAA?.records],
      ['NS', d.dns?.NS?.records], ['CAA', d.dns?.CAA?.records],
    ]);
    if (d.subdomains?.length) {
      lines.push(`## Subdomains (${d.subdomains.length})`, '', ...d.subdomains.map((s) => `- ${s}`), '');
    }
  }

  lines.push('---', '', 'Generated by GhostTrace from public registry, DNS and certificate-transparency data.');
  return lines.join('\n');
}

/* ────────────────────────────────────────────── history */

const readHistory = () => {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) ?? []; } catch { return []; }
};

function pushHistory(type, value, region) {
  const entries = readHistory().filter((e) => !(e.type === type && e.value === value));
  entries.unshift({ type, value, region: region || null, at: Date.now() });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, MAX_HISTORY)));
  renderHistory();
}

function renderHistory() {
  const entries = readHistory();
  $('#historyList').innerHTML = entries.length
    ? String(html`${entries.map((e) => html`
        <li><button type="button" data-type="${e.type}" data-value="${e.value}" data-region="${e.region ?? ''}">
          <span class="kind">${e.type}</span><span class="val">${e.value}</span>
        </button></li>
      `)}`)
    : '<li class="empty">Nothing yet.</li>';
}

/* ────────────────────────────────────────────── utilities */

function formatDate(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toISOString().slice(0, 10);
}

let toastTimer;
function toast(message) {
  let element = $('#toast');
  if (!element) {
    element = Object.assign(document.createElement('div'), { id: 'toast' });
    document.body.append(element);
  }
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove('show'), 2200);
}

/** Keep the address bar in step so results are linkable and reloadable. */
function syncUrl(type, value, region) {
  const params = new URLSearchParams({ type, q: value });
  if (region) params.set('region', region);
  history.replaceState(null, '', `${location.pathname}?${params}`);
}

/* ────────────────────────────────────────────── wiring */

function init() {
  initTheme();
  initRegions();
  renderHistory();

  document.querySelectorAll('.mode').forEach((button) => {
    button.addEventListener('click', () => setMode(button.dataset.mode));
  });

  // Delegated once: #results is replaced wholesale on every render.
  $('#results').addEventListener('click', onResultAction);

  $('#examples').addEventListener('click', (event) => {
    const button = event.target.closest('.example');
    if (!button) return;
    $('#query').value = button.dataset.value;
    $('#clearBtn').hidden = false;
    $('#searchForm').requestSubmit();
  });

  $('#searchForm').addEventListener('submit', (event) => {
    event.preventDefault();
    const value = $('#query').value.trim();
    if (value) runLookup(value, $('#region').hidden ? '' : $('#region').value);
  });

  $('#query').addEventListener('input', (event) => {
    $('#clearBtn').hidden = !event.target.value;
  });

  $('#clearBtn').addEventListener('click', () => {
    const input = $('#query');
    input.value = '';
    $('#clearBtn').hidden = true;
    input.focus();
  });

  $('#historyBtn').addEventListener('click', () => {
    const panel = $('#historyPanel');
    panel.hidden = !panel.hidden;
  });
  $('#closeHistory').addEventListener('click', () => { $('#historyPanel').hidden = true; });
  $('#clearHistory').addEventListener('click', () => {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
  });

  $('#historyList').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-type]');
    if (!button) return;
    setMode(button.dataset.type, { focus: false });
    $('#query').value = button.dataset.value;
    $('#clearBtn').hidden = false;
    if (button.dataset.region) $('#region').value = button.dataset.region;
    $('#historyPanel').hidden = true;
    $('#searchForm').requestSubmit();
  });

  // "/" focuses the input the way a search-first tool should.
  document.addEventListener('keydown', (event) => {
    if (event.key === '/' && document.activeElement !== $('#query')) {
      event.preventDefault();
      $('#query').focus();
    }
    if (event.key === 'Escape') $('#historyPanel').hidden = true;
  });

  fetch(api('health'))
    .then((r) => r.json())
    .then((body) => { $('#apiVersion').textContent = `API v${body.version}`; })
    .catch(() => { $('#apiVersion').textContent = 'API unreachable'; });

  // Restore a linked lookup, otherwise start on the default mode.
  const params = new URLSearchParams(location.search);
  const type = params.get('type');
  const query = params.get('q');

  setMode(MODES[type] ? type : 'phone', { focus: !query });

  if (query) {
    $('#query').value = query;
    $('#clearBtn').hidden = false;
    if (params.get('region')) $('#region').value = params.get('region');
    runLookup(query, params.get('region') ?? '');
  }
}

init();
