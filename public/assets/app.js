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
    examples: ['+1 212 343 3355', '+44 20 7123 4567', '+33 6 12 34 56 78', '+91 98765 43210'],
    hasRegion: true,
    deepNote: 'Deep scan does not change phone lookups.',
  },
  email: {
    placeholder: 'Enter an email address…',
    examples: ['security@github.com', 'm@mullenweg.com', 'info@stripe.com'],
    hasRegion: false,
    deepNote: 'Deep scan adds DKIM selector discovery on the address\'s domain.',
  },
  username: {
    placeholder: 'Enter a username or handle…',
    examples: ['torvalds', 'sindresorhus', 'octocat'],
    hasRegion: false,
    deepNote: 'Deep scan does not change username lookups.',
  },
  domain: {
    placeholder: 'Enter a domain name…',
    examples: ['github.com', 'anthropic.com', 'mattlavergne.com', 'wikipedia.org'],
    hasRegion: false,
    deepNote: 'Deep scan adds DKIM and SRV enumeration, subdomain resolution, takeover and origin-leak detection.',
  },
  ip: {
    placeholder: 'Enter an IPv4 or IPv6 address…',
    examples: ['8.8.8.8', '1.1.1.1', '140.82.114.3', '2606:4700:4700::1111'],
    hasRegion: false,
    deepNote: 'Deep scan adds BGP routing history and the registry record for the announcing AS.',
  },
  asn: {
    placeholder: 'Enter an AS number…',
    examples: ['AS15169', 'AS13335', 'AS32934', 'AS16509'],
    hasRegion: false,
    deepNote: 'Deep scan adds upstream providers, peers and internet-exchange presence.',
  },
};

const HISTORY_KEY = 'ghosttrace.history';
const THEME_KEY = 'ghosttrace.theme';
const DEPTH_KEY = 'ghosttrace.depth';
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
  $('#depthHint').textContent = config.deepNote;

  renderExamples(config.examples);
  if (focus) input.focus();
}

/* ────────────────────────────────────────────── scan depth */

const isDeep = () => $('#depthToggle').checked;

function initDepth() {
  const toggle = $('#depthToggle');
  toggle.checked = localStorage.getItem(DEPTH_KEY) === 'deep';
  toggle.addEventListener('change', () => {
    localStorage.setItem(DEPTH_KEY, toggle.checked ? 'deep' : 'standard');
  });
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
  if (isDeep()) params.set('depth', 'deep');

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
  const renderer = {
    phone: renderPhone, domain: renderDomain, ip: renderIp,
    email: renderEmail, username: renderUsername, asn: renderAsn,
  }[data.query.type];

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
    ip: () => [`IPv${data.query.version}`, data.classification?.kind, data.geolocation?.organization,
               data.registry?.name].filter(Boolean).join(' · '),
    email: () => [data.classification?.kind, data.mail?.provider].filter(Boolean).join(' · '),
    username: () => `found on ${data.summary?.found ?? 0} of ${data.summary?.checked ?? 0} platforms checked`,
    asn: () => [data.profile?.name ?? data.overview?.holder, data.profile?.country,
                data.profile?.rir].filter(Boolean).join(' · '),
  }[data.query.type]();

  const title = data.query.type === 'phone' ? (data.formats?.e164 ?? data.query.value) : data.query.value;

  return html`
    <div class="glass">
      <div class="result-head">
        <div class="result-title">
          <h2>${title}</h2>
          <p>${subtitle || '—'}${data.elapsedMs ? ` · ${data.elapsedMs} ms` : ''}${
            data.query.depth === 'deep' ? html` · <span class="pill">deep scan</span>` : ''}</p>
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
      ${pivots.map((p) => (p.url.startsWith('?')
        // A relative pivot is one this app can answer itself. Running it in
        // place keeps the investigation in one session instead of throwing the
        // user out to a reload.
        ? internalPivot(new URLSearchParams(p.url.slice(1)).get('type'),
                        new URLSearchParams(p.url.slice(1)).get('q'), p.label)
        : html`<a class="pivot" href="${p.url}" target="_blank" rel="noopener noreferrer">${p.label}${ICON_EXTERNAL}</a>`))}
    </div>
  `, { wide: true });
}

/**
 * A chip that runs another lookup here, on an entity this report discovered.
 *
 * This is what turns six separate tools into one investigation: a domain report
 * surfaces an address, the address is one click from its own report, and that
 * report surfaces an AS number. Doing it by hand — copying values between
 * modes — is where the thread gets dropped.
 */
function internalPivot(type, value, label = null) {
  if (!type || !value || !MODES[type]) return raw('');
  return html`<button type="button" class="pivot internal" data-lookup-type="${type}" data-lookup-value="${value}">
    <span class="kind">${type}</span>${label ?? value}
  </button>`;
}

/** A row of entity chips, each of which re-runs the app against that value. */
function pivotChips(type, values = [], { limit = 24 } = {}) {
  const list = [...new Set(values.filter(Boolean))].slice(0, limit);
  if (!list.length) return raw('');
  return html`<div class="pivots tight">${list.map((v) => internalPivot(type, v))}</div>`;
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

      ${d.numberingPlan ? card('Numbering plan (LERG)', html`
        ${dl([
          ['Rate centre', d.numberingPlan.rateCentre
            ? html`<strong>${d.numberingPlan.rateCentre}</strong>${d.numberingPlan.region ? `, ${d.numberingPlan.region}` : ''}` : null],
          ['Switch', d.numberingPlan.switchClli
            ? html`<span class="mono">${d.numberingPlan.switchClli}</span>${d.numberingPlan.switchName ? html` <span class="muted">${d.numberingPlan.switchName}</span>` : ''}` : null],
          ['Switch type', d.numberingPlan.switchType],
          ['Block holder', d.numberingPlan.company
            ? html`${d.numberingPlan.company}${d.numberingPlan.wholesaleCarrier ? html` <span class="pill warn">wholesale</span>` : ''}` : null],
          ['OCN', d.numberingPlan.ocn],
          ['Carrier type', { I: 'incumbent (ILEC)', C: 'competitive (CLEC)', W: 'wireless' }[d.numberingPlan.companyType] ?? d.numberingPlan.companyType],
          ['Incumbent', d.numberingPlan.incumbentCarrier],
          ['LATA', d.numberingPlan.lata],
          ['Block', d.numberingPlan.blockIdentifier === 'A' ? 'full 10,000-number block' : `pooled 1,000-block ${d.numberingPlan.blockIdentifier}`],
          ['Rate-centre location', d.numberingPlan.mapUrl
            ? html`<a href="${d.numberingPlan.mapUrl}" target="_blank" rel="noopener noreferrer">${d.numberingPlan.latitude}, ${d.numberingPlan.longitude}</a>`
            : null],
          ['LERG updated', d.numberingPlan.updated],
        ])}
        <p class="note">${d.numberingPlan.note}</p>
      `, { wide: true }) : raw('')}

      ${d.riskProfile ? card('Risk profile', html`
        <dl>
          <dt>Level</dt>
          <dd><span class="pill ${d.riskProfile.level === 'high' ? 'bad' : d.riskProfile.level === 'elevated' ? 'warn' : 'good'}">${d.riskProfile.level}</span></dd>
        </dl>
        <ul class="record-list">
          ${d.riskProfile.signals.map((s) => html`<li><strong>${s.signal}</strong><br><span class="muted">${s.detail}</span></li>`)}
        </ul>
      `, { wide: true }) : raw('')}

      ${card('Formats', dl([
        ['E.164', html`<span class="mono">${d.formats.e164}</span>`],
        ['International', html`<span class="mono">${d.formats.international}</span>`],
        ['National', html`<span class="mono">${d.formats.national}</span>`],
        ['RFC 3966', html`<span class="mono">${d.formats.rfc3966}</span>`],
        ['Example for region', d.example ? html`<span class="mono muted">${d.example}</span>` : null],
      ]))}

      ${d.attribution?.names?.length ? card('Attribution', html`
        ${d.attribution.best ? html`
          <dl>
            <dt>Best match</dt>
            <dd>
              <strong>${d.attribution.best.value}</strong>
              <span class="pill ${d.attribution.best.confidence === 'high' ? 'good' : d.attribution.best.confidence === 'low' ? 'warn' : ''}">${d.attribution.best.confidence} confidence</span>
            </dd>
          </dl>` : ''}
        <h4 class="rrtype">All candidates</h4>
        <ul class="record-list">
          ${d.attribution.names.map((n) => html`<li>
            ${n.value}
            <span class="pill ${n.confidence === 'high' ? 'good' : n.confidence === 'low' ? 'warn' : ''}">${n.confidence}</span>
            <span class="muted">${n.source}${n.corroboration > 1 ? ` · corroborated by ${n.corroboration} sources` : ''}</span>
            ${n.detail ? html`<br><span class="muted">${n.detail}</span>` : ''}
          </li>`)}
        </ul>
        <p class="note">Checked: ${d.attribution.checked.join(', ')}. Confidence reflects what a hit proves —
          <em>high</em> means the entity published this number as its own, <em>low</em> means a search engine surfaced it.</p>
      `, { wide: true, count: d.attribution.names.length }) : raw('')}

      ${d.filings?.companies?.length ? card('SEC filings', html`
        <div class="scroll"><table>
          <thead><tr><th>Company</th><th>Filed number</th><th>Industry</th><th>Location</th></tr></thead>
          <tbody>${d.filings.companies.map((c) => html`
            <tr>
              <td><a href="${c.edgarUrl}" target="_blank" rel="noopener noreferrer">${c.name}</a>
                ${c.tickers?.length ? html` <span class="pill">${c.tickers.join(', ')}</span>` : ''}
                ${c.confirmed ? html` <span class="pill good">filed</span>` : html` <span class="pill warn">mentioned</span>`}</td>
              <td class="mono">${c.phone ?? '—'}</td>
              <td>${c.industry || '—'}</td>
              <td>${c.location ?? '—'}</td>
            </tr>`)}</tbody>
        </table></div>
        <p class="note">${d.filings.totalFilings} filing(s) contain this number.
          <strong>Filed</strong> means it is the number on that company's own EDGAR profile;
          <strong>mentioned</strong> means it merely appears in their filings and may belong to an agent or counterparty.</p>
      `, { wide: true, count: d.filings.companies.length }) : raw('')}

      ${d.search?.results?.length ? card('Search footprint', html`
        <div class="scroll">
          ${d.search.results.map((r) => html`
            <h4 class="rrtype"><a href="${r.url}" target="_blank" rel="noopener noreferrer">${r.title ?? r.url}</a></h4>
            ${r.snippet ? html`<p class="note">${r.snippet}</p>` : ''}
          `)}
        </div>
        <p class="note">Unverified search results for <span class="mono">${d.search.query}</span>.
          Reverse-lookup spam sites are filtered out of the name candidates but may still appear here.</p>
      `, { wide: true, count: d.search.resultCount }) : raw('')}

      ${d.encyclopedia?.articles?.length ? card('Wikipedia', html`
        ${d.encyclopedia.articles.map((a) => html`
          <h4 class="rrtype"><a href="${a.url}" target="_blank" rel="noopener noreferrer">${a.title}</a></h4>
          ${a.snippet ? html`<p class="note">${a.snippet}</p>` : ''}
        `)}
        <p class="note">A number printed in an encyclopedia article belongs to something notable and named.</p>
      `, { wide: true, count: d.encyclopedia.articles.length }) : raw('')}

      ${d.places?.length ? card('Matched in OpenStreetMap', html`
        ${d.places.map((pl) => html`
          <h4 class="rrtype">${pl.name}${pl.category ? html` <span class="pill">${pl.category}</span>` : ''}
            ${pl.matchedTag && pl.matchedTag !== 'phone' ? html` <span class="pill warn">${pl.matchedTag}</span>` : ''}</h4>
          ${dl([
            ['Brand', pl.brand],
            ['Operator', pl.operator],
            ['Address', pl.address],
            ['Opening hours', pl.openingHours],
            ['Website', pl.website ? html`<a href="${pl.website}" target="_blank" rel="noopener noreferrer">${pl.website}</a>` : null],
            ['Email', pl.email ? internalPivot('email', pl.email) : null],
            ['Social', pl.socials?.length
              ? html`<ul class="record-list compact">${pl.socials.map((s) => html`<li>${s.platform}: <span class="mono">${s.handle}</span></li>`)}</ul>`
              : null],
            ['Listed number', html`<span class="mono">${pl.phone}</span>`],
            ['Coordinates', pl.mapUrl
              ? html`<a href="${pl.mapUrl}" target="_blank" rel="noopener noreferrer">${pl.latitude}, ${pl.longitude}</a>` : null],
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

      ${d.variants?.length ? card('Written forms', html`
        <div class="tags spaced">${d.variants.map((v) => html`<span class="tag">${v}</span>`)}</div>
        <p class="note">Search engines, forums and leaked datasets each write numbers differently, and a search for
          one spelling misses the rest. These are the forms worth trying by hand.</p>
      `, { wide: true, count: d.variants.length }) : raw('')}

      ${d.caveats?.length ? card('Read this before acting on it', html`
        <ul class="caveats">${d.caveats.map((c) => html`<li>${c}</li>`)}</ul>
      `, { wide: true }) : raw('')}

      ${pivotsCard(d.pivots)}
    </div>
  `;
}

/* ─────────────────────────────── email */

function renderEmail(d) {
  const g = d.gravatar;
  const id = d.identity;
  const c = d.classification;

  return html`
    <div class="cards">
      ${card('Address', dl([
        ['Kind', html`<span class="pill ${c.isDisposable ? 'bad' : c.kind === 'organisation mailbox' ? 'good' : ''}">${c.kind}</span>`],
        ['What that means', html`<span class="muted">${c.meaning}</span>`],
        ['Local part', html`<span class="mono">${d.address.local}</span>`],
        ['Domain', internalPivot('domain', d.address.domain)],
        ['Canonical form', d.address.canonical !== d.query.value ? html`<span class="mono">${d.address.canonical}</span>` : null],
        ['Sub-address tag', c.subAddressTag ? html`<span class="pill warn">+${c.subAddressTag}</span>` : null],
        ['Likely typo for', c.likelyTypo ? html`<span class="pill bad">${c.likelyTypo}</span>` : null],
        ['MD5', html`<span class="mono tiny">${d.address.md5}</span>`],
        ['SHA-256', html`<span class="mono tiny">${d.address.sha256}</span>`],
      ]))}

      ${g?.exists ? card('Gravatar profile', html`
        <div class="profile">
          ${g.avatarUrl ? html`<img class="avatar" src="${g.avatarUrl}" alt="" width="64" height="64" referrerpolicy="no-referrer">` : ''}
          <div>
            <h4 class="rrtype">${g.displayName ?? g.username ?? 'Profile'}</h4>
            ${g.aboutMe ? html`<p class="note">${g.aboutMe}</p>` : ''}
          </div>
        </div>
        ${dl([
          ['Name', g.name],
          ['Username', g.username],
          ['Location', g.location],
          ['Company', g.company],
          ['Job title', g.jobTitle],
          ['Profile', html`<a href="${g.profileUrl}" target="_blank" rel="noopener noreferrer">${g.profileUrl}</a>`],
        ])}
      `, { wide: true }) : raw('')}

      ${id?.accounts?.length ? card('Linked accounts', html`
        <ul class="record-list">
          ${id.accounts.map((a) => html`<li>
            <strong>${a.platform}</strong>
            ${a.username ? html` <span class="mono">${a.username}</span>` : ''}
            ${a.verified ? html` <span class="pill good">verified</span>` : html` <span class="pill warn">unconfirmed</span>`}
            ${a.url ? html`<br><a href="${a.url}" target="_blank" rel="noopener noreferrer">${a.url}</a>` : ''}
            <span class="muted"> · ${a.source}</span>
          </li>`)}
        </ul>
        <p class="note">A verified account is one the address owner proved control of, or one that publishes this
          exact address on its public profile. Unconfirmed entries came back from a fuzzy search and are leads only.</p>
      `, { wide: true, count: id.accounts.length }) : raw('')}

      ${d.accounts?.matches?.length ? card('GitHub search', html`
        <div class="scroll"><table>
          <thead><tr><th>Account</th><th>Name</th><th>Public email</th><th>Status</th></tr></thead>
          <tbody>${d.accounts.matches.map((m) => html`
            <tr>
              <td><a href="${m.url}" target="_blank" rel="noopener noreferrer">${m.username}</a></td>
              <td>${m.name ?? '—'}${m.company ? html` <span class="muted">${m.company}</span>` : ''}</td>
              <td class="mono">${m.publicEmail ?? '—'}</td>
              <td>${m.confirmed ? html`<span class="pill good">confirmed</span>` : html`<span class="pill warn">lead</span>`}</td>
            </tr>`)}</tbody>
        </table></div>
        <p class="note">${d.accounts.matches[0]?.confirmation}</p>
      `, { wide: true, count: d.accounts.candidates }) : raw('')}

      ${d.mail ? card('Mail delivery', dl([
        ['Deliverable', d.mail.nullMx
          ? html`<span class="pill bad">refuses all mail</span>`
          : d.mail.deliverable ? html`<span class="pill good">a mail server exists</span>` : html`<span class="pill bad">nowhere to deliver</span>`],
        ['Provider', d.mail.provider],
        ['MX hosts', d.mail.mxHosts?.length
          ? html`<ul class="record-list compact">${d.mail.mxHosts.map((h) => html`<li><span class="mono">${h.host}</span> <span class="muted">priority ${h.priority ?? '—'}</span></li>`)}</ul>`
          : html`<span class="muted">none</span>`],
        ['Fallback A', d.mail.fallbackA?.length ? html`<span class="mono">${d.mail.fallbackA.join(', ')}</span>` : null],
        ['SPF', d.mail.spf ? html`<span class="pill good">present</span>` : html`<span class="pill warn">absent</span>`],
        ['DMARC', d.mail.dmarcPolicy ? html`<span class="pill good">p=${d.mail.dmarcPolicy}</span>` : html`<span class="pill warn">absent</span>`],
        ['MTA-STS', d.mail.mtaSts ? html`<span class="pill good">present</span>` : null],
      ])) : raw('')}

      ${d.domainRegistration && !d.domainRegistration.skipped ? card('Domain registration', dl([
        ['Domain', internalPivot('domain', d.domainRegistration.domain)],
        ['Created', formatDate(d.domainRegistration.created)],
        ['Age', d.domainRegistration.ageDays != null
          ? html`${d.domainRegistration.ageDays.toLocaleString()} days ${d.domainRegistration.ageDays < 90
              ? html`<span class="pill bad">very new</span>` : ''}` : null],
        ['Registrar', d.domainRegistration.registrar],
        ['Registrant', d.domainRegistration.registrant],
      ])) : raw('')}

      ${d.breaches ? card('Breach exposure', d.breaches.breached ? html`
        <div class="scroll"><table>
          <thead><tr><th>Breach</th><th>Date</th><th>Exposed</th></tr></thead>
          <tbody>${d.breaches.breaches.map((b) => html`
            <tr>
              <td>${b.name}${b.sensitive ? html` <span class="pill bad">sensitive</span>` : ''}</td>
              <td>${b.date ?? '—'}</td>
              <td>${(b.data ?? []).slice(0, 6).join(', ')}</td>
            </tr>`)}</tbody>
        </table></div>
      ` : html`<p class="muted">Have I Been Pwned has no record of this address.</p>`,
        { wide: d.breaches.breached, count: d.breaches.count }) : raw('')}

      ${d.sendingPlatforms?.found?.length ? card('Sending platforms', html`
        <div class="tags spaced">${d.sendingPlatforms.found.map((f) => html`<span class="tag">${f.selector} · ${f.platform}</span>`)}</div>
        <p class="note">DKIM selectors published on this domain. Each one is a service authorised to send mail as it.</p>
      `, { count: d.sendingPlatforms.found.length }) : raw('')}

      ${d.usernameCandidates?.length ? card('Try as a username', html`
        ${pivotChips('username', d.usernameCandidates)}
        <p class="note">Derived from the local part. People reuse handles far more than they reuse addresses,
          so these are worth checking — but a match is a lead, not proof they are the same person.</p>
      `, { wide: true }) : raw('')}

      ${d.caveats?.length ? card('Read this before acting on it', html`
        <ul class="caveats">${d.caveats.map((c) => html`<li>${c}</li>`)}</ul>
      `, { wide: true }) : raw('')}

      ${pivotsCard(d.pivots)}
    </div>
  `;
}

/* ─────────────────────────────── username */

function renderUsername(d) {
  const id = d.identity;

  return html`
    <div class="cards">
      ${card('Summary', dl([
        ['Found', html`<span class="pill good">${d.summary.found}</span> of ${d.summary.checked} platforms checked`],
        ['Not found', d.summary.absent],
        ['Could not check', d.summary.unavailable
          ? html`<span class="pill warn">${d.summary.unavailable}</span>` : 0],
        ['Best name', id.bestName ? html`<strong>${id.bestName}</strong>` : html`<span class="muted">none reported</span>`],
        ['Corroboration', id.corroboration > 1
          ? html`<span class="pill good">${id.corroboration} platforms agree</span>`
          : html`<span class="muted">no cross-platform agreement</span>`],
        ['Earliest account', id.earliest ? `${id.earliest.joined} on ${id.earliest.platform}` : null],
      ]))}

      ${id.names?.length > 1 ? card('Conflicting names', html`
        <ul class="record-list">
          ${id.names.map((n) => html`<li>${n.value} <span class="muted">${n.sources.join(', ')}</span></li>`)}
        </ul>
        <p class="note">More than one self-reported name across these accounts. A popular handle is often claimed
          by different people on different platforms — do not merge them into one identity without more evidence.</p>
      `, { wide: true }) : raw('')}

      ${d.accounts?.length ? card('Accounts found', html`
        ${d.accounts.map((a) => html`
          <h4 class="rrtype">
            <a href="${a.url}" target="_blank" rel="noopener noreferrer">${a.platform}</a>
            <span class="pill">${a.category}</span>
          </h4>
          ${dl([
            ['Name', a.displayName],
            ['Bio', a.bio],
            ['Location', a.location],
            ['Company', a.company],
            ['Email', a.email ? internalPivot('email', a.email) : null],
            ['Website', a.website ? html`<a href="${a.website}" target="_blank" rel="noopener noreferrer">${a.website}</a>` : null],
            ['Joined', a.joined],
            ['Followers', a.followers],
            ['Detail', a.extra ? html`<span class="muted mono tiny">${JSON.stringify(a.extra)}</span>` : null],
            ['Links', a.links?.length
              ? html`<ul class="record-list compact">${a.links.map((l) => html`<li>${l.name ? html`${l.name}: ` : ''}${l.value}${l.verified ? html` <span class="pill good">verified</span>` : ''}</li>`)}</ul>`
              : null],
            ['Proofs', a.proofs?.length
              ? html`<ul class="record-list compact">${a.proofs.map((p) => html`<li>${p.platform}: <span class="mono">${p.username}</span></li>`)}</ul>`
              : null],
          ])}
        `)}
      `, { wide: true, count: d.accounts.length }) : raw('')}

      ${id.declaredHandles?.length ? card('Declared account links', html`
        <ul class="record-list">
          ${id.declaredHandles.map((h) => html`<li>
            <strong>${h.platform}</strong> <span class="mono">${h.username}</span>
            <span class="pill ${h.proof === 'cryptographic proof' ? 'good' : ''}">${h.proof}</span>
            <span class="muted"> · via ${h.via}</span>
          </li>`)}
        </ul>
        <p class="note">Handles this person pointed at from their own profiles. A cryptographic proof is a signed
          statement posted on the other platform, so it is verifiable; a self-declaration is not, though in
          practice people rarely lie about their own accounts.</p>
      `, { wide: true, count: id.declaredHandles.length }) : raw('')}

      ${id.links?.length ? card('Published links', html`
        <ul class="record-list">
          ${id.links.map((l) => html`<li>
            <a href="${l.url}" target="_blank" rel="noopener noreferrer">${l.url}</a>
            ${l.verified ? html` <span class="pill good">verified</span>` : ''}
            <span class="muted"> · ${l.source}</span>
          </li>`)}
        </ul>
      `, { wide: true, count: id.links.length }) : raw('')}

      ${id.emails?.length ? card('Email addresses', html`
        ${pivotChips('email', id.emails.map((e) => e.value))}
        <p class="note">Published by the account holder on their own profile.</p>
      `, { wide: true }) : raw('')}

      ${id.joinDates?.length ? card('Registration timeline', html`
        <ul class="record-list">
          ${id.joinDates.map((j) => html`<li><span class="mono">${j.joined}</span> — ${j.platform}</li>`)}
        </ul>
      `, { count: id.joinDates.length }) : raw('')}

      ${d.unavailable?.length ? card('Could not be checked', html`
        <ul class="record-list">
          ${d.unavailable.map((u) => html`<li>
            <a href="${u.url}" target="_blank" rel="noopener noreferrer">${u.platform}</a>
            <br><span class="muted">${u.error}</span>
          </li>`)}
        </ul>
        <p class="note">These are unknown, not absent. Most are rate limits that meter by source address.</p>
      `, { count: d.unavailable.length }) : raw('')}

      ${d.notFound?.length ? card('Not found', html`
        <ul class="record-list compact">
          ${d.notFound.map((n) => html`<li>${n.platform} <span class="muted">${n.meaning}</span></li>`)}
        </ul>
      `, { count: d.notFound.length }) : raw('')}

      ${d.manualChecks?.length ? card('Check these by hand', html`
        <ul class="record-list">
          ${d.manualChecks.map((m) => html`<li>
            <a href="${m.url}" target="_blank" rel="noopener noreferrer">${m.platform}</a>
            <span class="muted"> — ${m.reason}</span>
          </li>`)}
        </ul>
        <p class="note">None of these can be checked honestly from a server, so they are not guessed at.
          Opening them in your own browser is the reliable way to answer them.</p>
      `, { wide: true, count: d.manualChecks.length }) : raw('')}

      ${d.caveats?.length ? card('Read this before acting on it', html`
        <ul class="caveats">${d.caveats.map((c) => html`<li>${c}</li>`)}</ul>
      `, { wide: true }) : raw('')}

      ${pivotsCard(d.pivots)}
    </div>
  `;
}

/* ─────────────────────────────── asn */

function renderAsn(d) {
  if (!d.public) {
    return html`<div class="cards">${card('Not a public AS', html`<p class="muted">${d.summary}</p>`, { wide: true })}</div>`;
  }

  const p = d.profile;
  const n = d.network;

  return html`
    <div class="cards">
      ${card('Network', dl([
        ['Name', p?.name ?? d.overview?.holder],
        ['Description', p?.description],
        ['Country', p?.country],
        ['RIR', p?.rir],
        ['Allocated', formatDate(p?.allocated)],
        ['Announced', d.overview?.announced === true ? html`<span class="pill good">yes</span>`
          : d.overview?.announced === false ? html`<span class="pill warn">no</span>` : null],
        ['Website', p?.website ? html`<a href="${p.website}" target="_blank" rel="noopener noreferrer">${p.website}</a>` : null],
        ['Registered address', p?.ownerAddress],
      ]))}

      ${d.registry ? card('Registry record', dl([
        ['Handle', d.registry.handle],
        ['Name', d.registry.name],
        ['Holder', d.registry.registrant?.organization ?? d.registry.registrant?.name],
        ['Country', d.registry.country],
        ['Registered', formatDate(d.registry.registered)],
        ['Updated', formatDate(d.registry.updated)],
        ['Range', d.registry.startAutnum != null
          ? `AS${d.registry.startAutnum} – AS${d.registry.endAutnum}` : null],
      ])) : raw('')}

      ${d.contacts?.length ? card('Contacts', html`
        <ul class="record-list">
          ${d.contacts.map((c) => html`<li>
            <span class="pill ${c.role === 'abuse' ? 'warn' : ''}">${c.role}</span>
            ${c.value.includes('@') ? html`<a href="mailto:${c.value}">${c.value}</a>` : c.value}
            <span class="muted"> · ${c.source}</span>
          </li>`)}
        </ul>
        <p class="note">Where a netblock's own record is stale or redacted, the AS-level abuse address and the
          operator's published NOC contact usually are not.</p>
      `, { wide: true, count: d.contacts.length }) : raw('')}

      ${d.prefixes ? card('Announced prefixes', html`
        ${dl([
          ['IPv4 prefixes', d.prefixes.ipv4Count],
          ['IPv6 prefixes', d.prefixes.ipv6Count],
          ['IPv4 addresses', d.prefixes.ipv4Addresses?.toLocaleString()],
        ])}
        <div class="scroll">
          <ul class="record-list compact">
            ${d.prefixes.ipv4.map((x) => html`<li><span class="mono">${x.prefix}</span>${x.description ? html` <span class="muted">${x.description}</span>` : ''}</li>`)}
            ${d.prefixes.ipv6.map((x) => html`<li><span class="mono">${x.prefix}</span>${x.description ? html` <span class="muted">${x.description}</span>` : ''}</li>`)}
          </ul>
        </div>
        ${d.prefixes.truncated ? html`<p class="note">Truncated — the full list is on BGPView.</p>` : ''}
      `, { wide: true, count: d.prefixes.ipv4Count + d.prefixes.ipv6Count }) : raw('')}

      ${d.upstreams?.networks?.length ? card('Upstream transit', html`
        <div class="scroll"><table>
          <thead><tr><th>AS</th><th>Name</th><th>Country</th></tr></thead>
          <tbody>${d.upstreams.networks.map((u) => html`
            <tr>
              <td>${internalPivot('asn', u.asn)}</td>
              <td>${u.name ?? '—'}${u.description ? html` <span class="muted">${u.description}</span>` : ''}</td>
              <td>${u.country ?? '—'}</td>
            </tr>`)}</tbody>
        </table></div>
        <p class="note">These networks carry this AS to the rest of the internet. They hold a contract with its
          operator, which makes them the effective place to escalate abuse.</p>
      `, { wide: true, count: d.upstreams.count }) : raw('')}

      ${d.peers?.networks?.length ? card('Peers', html`
        <div class="scroll"><table>
          <thead><tr><th>AS</th><th>Name</th><th>Country</th></tr></thead>
          <tbody>${d.peers.networks.map((u) => html`
            <tr><td>${internalPivot('asn', u.asn)}</td><td>${u.name ?? '—'}</td><td>${u.country ?? '—'}</td></tr>`)}</tbody>
        </table></div>
      `, { wide: true, count: d.peers.count }) : raw('')}

      ${d.exchanges?.exchanges?.length ? card('Internet exchanges', html`
        <div class="scroll"><table>
          <thead><tr><th>Exchange</th><th>City</th><th>Country</th><th>Speed</th></tr></thead>
          <tbody>${d.exchanges.exchanges.map((x) => html`
            <tr>
              <td>${x.name ?? '—'}</td><td>${x.city ?? '—'}</td><td>${x.country ?? '—'}</td>
              <td>${x.speedMbps ? `${(x.speedMbps / 1000).toFixed(0)} Gbps` : '—'}</td>
            </tr>`)}</tbody>
        </table></div>
        <p class="note">Exchange presence is the closest thing an AS has to a physical footprint: equipment in
          those buildings, in those countries.</p>
      `, { wide: true, count: d.exchanges.count }) : raw('')}

      ${n ? card('Operator profile', dl([
        ['Name', n.name],
        ['Also known as', n.alsoKnownAs],
        ['Type', n.networkType],
        ['Scope', n.scope],
        ['Traffic', n.trafficLevels],
        ['Traffic ratio', n.ratios],
        ['Peering policy', n.peeringPolicy],
        ['IPv4 / IPv6 prefixes', n.prefixesV4 != null ? `${n.prefixesV4.toLocaleString()} / ${(n.prefixesV6 ?? 0).toLocaleString()}` : null],
        ['Exchanges / facilities', n.exchangeCount != null ? `${n.exchangeCount} / ${n.facilityCount}` : null],
        ['IRR AS-SET', n.irrAsSet ? html`<span class="mono">${n.irrAsSet}</span>` : null],
        ['NOC contact', n.nocContact ? html`<a href="mailto:${n.nocContact}">${n.nocContact}</a>` : null],
        ['Looking glass', n.lookingGlass ? html`<a href="${n.lookingGlass}" target="_blank" rel="noopener noreferrer">open</a>` : null],
        ['PeeringDB', html`<a href="${n.peeringDbUrl}" target="_blank" rel="noopener noreferrer">record</a>`],
      ])) : raw('')}

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

  const agreement = d.geolocationAgreement;

  return html`
    <div class="cards">
      ${d.classification ? card('What this address is', html`
        <dl>
          <dt>Kind</dt>
          <dd><span class="pill ${d.classification.kind === 'datacenter' ? '' : 'warn'}">${d.classification.kind}</span>
            ${d.classification.operator ? html` <span class="muted">${d.classification.operator}</span>` : ''}</dd>
          <dt>What that means</dt><dd>${d.classification.meaning}</dd>
        </dl>
        ${d.classification.evidence?.length ? html`
          <h4 class="rrtype">Evidence</h4>
          <ul class="record-list compact">
            ${d.classification.evidence.map((e) => html`<li><span class="pill">${e.signal}</span> ${e.detail}</li>`)}
          </ul>` : ''}
      `, { wide: true }) : raw('')}

      ${d.geofeed ? card('Operator geofeed', html`
        ${dl([
          ['Prefix', html`<span class="mono">${d.geofeed.prefix}</span>`],
          ['Country', d.geofeed.country],
          ['Region', d.geofeed.region],
          ['City', d.geofeed.city],
          ['Postal', d.geofeed.postal],
          ['Source', html`<a href="${d.geofeed.source}" target="_blank" rel="noopener noreferrer">${d.geofeed.source}</a>`],
        ])}
        <p class="note">${d.geofeed.note} This is the network operator's own published statement about where these
          addresses are deployed, and it outranks every commercial geolocation database.</p>
      `, { wide: true }) : d.geofeedStatus ? card('Operator geofeed', html`
        <p class="muted">${d.geofeedStatus.note}</p>
        <p class="note">The operator advertises a geofeed at
          <a href="${d.geofeedStatus.url}" target="_blank" rel="noopener noreferrer">${d.geofeedStatus.url}</a>,
          so they maintain self-published geolocation for some of their space — just not for this block.</p>
      `, { wide: true }) : raw('')}

      ${geo ? card('Geolocation', dl([
        ['Country', geo.flag ? `${geo.flag} ${geo.country}` : geo.country],
        ['Region', geo.region],
        ['City', geo.city],
        ['Postal', geo.postal],
        // Nested as one template: concatenating a Safe with a string collapses
        // it to plain text, which then gets escaped on the way out.
        ['Precision', html`<span class="pill warn">${geo.precision}-level</span>${
          geo.provider ? html` <span class="muted">via ${geo.provider}</span>` : ''}`],
        ['Timezone', geo.timezone ? `${geo.timezone.id} (UTC${geo.timezone.utcOffset})` : null],
        ['Coordinates', geo.mapUrl
          ? html`<a href="${geo.mapUrl}" target="_blank" rel="noopener noreferrer">${geo.latitude}, ${geo.longitude}</a>`
          : null],
      ])) : raw('')}

      ${agreement ? card('Provider agreement', html`
        ${dl([
          ['Providers answering', agreement.providers],
          ['Country consensus', agreement.countryConsensus
            ? html`<span class="pill good">agreed</span>` : html`<span class="pill bad">disputed</span>`],
          ['Cities returned', agreement.cities?.length ? agreement.cities.join(', ') : null],
          ['Widest disagreement', agreement.spreadKm != null
            ? html`<span class="pill ${agreement.spreadKm > 100 ? 'warn' : 'good'}">${agreement.spreadKm} km</span>` : null],
        ])}
        <p class="note">${agreement.verdict}</p>
        ${d.geolocationProviders?.length ? html`
          <div class="scroll"><table>
            <thead><tr><th>Provider</th><th>Country</th><th>City</th><th>Coordinates</th></tr></thead>
            <tbody>${d.geolocationProviders.map((p) => html`
              <tr>
                <td>${p.provider}</td><td>${p.countryCode ?? '—'}</td><td>${p.city ?? '—'}</td>
                <td class="mono tiny">${p.latitude != null ? `${p.latitude}, ${p.longitude}` : '—'}</td>
              </tr>`)}</tbody>
          </table></div>` : ''}
      `, { wide: true }) : raw('')}

      ${card('Network', dl([
        ['Organisation', geo?.organization],
        ['ISP', geo?.isp],
        ['ASN', geo?.asn ? internalPivot('asn', geo.asn) : null],
        ['Reverse DNS', d.reverseDns ? html`<span class="mono">${d.reverseDns}</span>` : html`<span class="muted">none published</span>`],
        ['PTR reveals', d.reverseDnsIntel
          ? html`${d.reverseDnsIntel.platform ?? ''}${d.reverseDnsIntel.region ? html` <span class="pill good">${d.reverseDnsIntel.region}</span>` : ''}${
              d.reverseDnsIntel.kind ? html` <span class="muted">${d.reverseDnsIntel.kind}</span>` : ''}`
          : null],
        ['Netblock', reg?.cidr ?? reg?.range],
        ['Allocation', reg?.type],
        ['Registry', reg?.registry],
        ['RIR allocation', d.allocation?.allocatedPrefix
          ? html`<span class="mono">${d.allocation.allocatedPrefix}</span> <span class="muted">${d.allocation.rir ?? ''} ${d.allocation.allocationDate ?? ''}</span>`
          : null],
      ]))}

      ${d.blocklists ? card('DNS blocklists', d.blocklists.listedOn ? html`
        <ul class="record-list">
          ${d.blocklists.listings.map((l) => html`<li>
            <span class="pill bad">${l.name}</span> ${l.reasons.join('; ')}
            <span class="muted mono tiny"> ${l.codes.join(', ')}</span>
          </li>`)}
        </ul>
        <p class="note">This is what a receiving mail server sees when this address tries to deliver.
          ${d.blocklists.unavailable?.length
            ? `${d.blocklists.unavailable.length} zone(s) could not be used: ${d.blocklists.unavailable.map((u) => `${u.name} (${u.reason})`).join(', ')}.`
            : ''}</p>
      ` : html`<p class="muted">Not listed on any of the ${d.blocklists.usable} blocklists that answered.</p>
        ${d.blocklists.unavailable?.length ? html`<p class="note">${d.blocklists.unavailable.map((u) => `${u.name}: ${u.reason}`).join(' · ')}</p>` : ''}`,
        { wide: d.blocklists.listedOn > 0, count: d.blocklists.listedOn }) : raw('')}

      ${d.anonymity?.tor ? card('Tor relay', dl([
        ['Nickname', d.anonymity.relay.nickname],
        ['Role', html`${d.anonymity.relay.isExit ? html`<span class="pill bad">exit</span>` : ''}
          ${d.anonymity.relay.isGuard ? html`<span class="pill warn">guard</span>` : ''}
          ${(d.anonymity.relay.flags ?? []).join(', ')}`],
        ['Running', d.anonymity.relay.running === true ? html`<span class="pill good">yes</span>` : 'no'],
        ['First seen', d.anonymity.relay.firstSeen],
        ['Last seen', d.anonymity.relay.lastSeen],
        ['Bandwidth', d.anonymity.relay.bandwidthMbps ? `${d.anonymity.relay.bandwidthMbps} Mbps` : null],
        ['Operator contact', d.anonymity.relay.contact],
        ['Platform', d.anonymity.relay.platform],
        ['Fingerprint', d.anonymity.relay.fingerprint ? html`<span class="mono tiny">${d.anonymity.relay.fingerprint}</span>` : null],
      ]), { wide: true }) : raw('')}

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
        ['Escalation path', d.abuseContacts?.emails?.length
          ? html`${d.abuseContacts.emails.map((e) => html`<a href="mailto:${e}">${e}</a> `)}<span class="muted">via ${d.abuseContacts.authoritativeRir ?? 'the RIR hierarchy'}</span>`
          : null],
        ['Registry notes', reg.remarks?.length
          ? html`<ul class="record-list compact">${reg.remarks.map((r) => html`<li>${r}</li>`)}</ul>` : null],
      ])) : raw('')}

      ${d.routingHistory ? card('Routing history', d.routingHistory.origins?.length ? html`
        <div class="scroll"><table>
          <thead><tr><th>Origin AS</th><th>First seen</th><th>Last seen</th><th>Prefixes</th></tr></thead>
          <tbody>${d.routingHistory.origins.map((o) => html`
            <tr>
              <td>${internalPivot('asn', o.asn)}</td>
              <td>${o.firstSeen ?? '—'}</td><td>${o.lastSeen ?? 'current'}</td>
              <td class="mono tiny">${(o.prefixes ?? []).join(', ')}</td>
            </tr>`)}</tbody>
        </table></div>
        <p class="note">${d.routingHistory.changedHands
          ? 'More than one network has announced this prefix over the window. That means the block was transferred, leased, or hijacked — worth establishing which.'
          : 'A single origin across the whole window, which is what a stable, legitimately-held block looks like.'}
          ${d.routingHistory.window ? ` Window: ${d.routingHistory.window}.` : ''}</p>
      ` : html`<p class="muted">No routing history available for this prefix.</p>`, { wide: true }) : raw('')}

      ${d.shodan?.services?.length ? card('Service banners', html`
        <div class="scroll"><table>
          <thead><tr><th>Port</th><th>Product</th><th>Detail</th><th>Seen</th></tr></thead>
          <tbody>${d.shodan.services.map((s) => html`
            <tr>
              <td class="mono">${s.port}${s.transport ? `/${s.transport}` : ''}</td>
              <td>${[s.product, s.version].filter(Boolean).join(' ') || s.module || '—'}</td>
              <td>${[s.title, s.server, s.certificateSubject].filter(Boolean).join(' · ') || '—'}</td>
              <td>${formatDate(s.timestamp) ?? '—'}</td>
            </tr>`)}</tbody>
        </table></div>
      `, { wide: true, count: d.shodan.services.length }) : raw('')}

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
        <div class="scroll">${pivotChips('domain', d.hostedDomains.domains, { limit: 100 })}</div>
        <p class="note">
          ${d.hostedDomains.shared
            ? 'Shared hosting or a CDN front — this address does not identify a single owner.'
            : 'Few names resolve here, which suggests dedicated hosting.'}
          ${d.hostedDomains.truncated ? ' Showing the first 100.' : ''}
          ${d.hostedDomains.provider ? ` Source: ${d.hostedDomains.provider}.` : ''}
        </p>
      ` : html`<p class="muted">No domains found resolving to this address.</p>`,
        { wide: d.hostedDomains.count > 12, count: d.hostedDomains.count }) : raw('')}

      ${d.threat ? card('Attack history', d.threat.seen ? dl([
        ['Networks attacked', html`<span class="pill ${d.threat.targets > 100 ? 'bad' : 'warn'}">${(d.threat.targets ?? 0).toLocaleString()}</span>`],
        ['Events logged', (d.threat.records ?? 0).toLocaleString()],
        ['First seen', formatDate(d.threat.firstSeen)],
        ['Last seen', formatDate(d.threat.lastSeen)],
        ['Threat feeds', d.threat.threatFeeds?.length
          ? html`<div class="tags">${d.threat.threatFeeds.map((f) => html`<span class="tag bad">${f}</span>`)}</div>` : null],
        ['Cloud provider', d.threat.cloudProvider],
      ]) : html`<p class="muted">SANS Internet Storm Center sensors have never logged traffic from this address.</p>`,
        { count: d.threat.seen ? d.threat.threatFeeds?.length || null : null }) : raw('')}

      ${d.network ? card('Network operator', dl([
        ['Name', d.network.name],
        ['Also known as', d.network.alsoKnownAs],
        ['Type', d.network.networkType],
        ['Scope', d.network.scope],
        ['Traffic', d.network.trafficLevels],
        ['Traffic ratio', d.network.ratios],
        ['IPv4 / IPv6 prefixes', d.network.prefixesV4 != null
          ? `${d.network.prefixesV4.toLocaleString()} / ${(d.network.prefixesV6 ?? 0).toLocaleString()}` : null],
        ['Exchanges / facilities', d.network.exchangeCount != null
          ? `${d.network.exchangeCount} / ${d.network.facilityCount}` : null],
        ['Peering policy', d.network.peeringPolicy],
        ['IRR AS-SET', d.network.irrAsSet ? html`<span class="mono">${d.network.irrAsSet}</span>` : null],
        ['Website', d.network.website ? html`<a href="${d.network.website}" target="_blank" rel="noopener noreferrer">${d.network.website}</a>` : null],
        ['PeeringDB', html`<a href="${d.network.peeringDbUrl}" target="_blank" rel="noopener noreferrer">${d.network.asn}</a>`],
      ])) : raw('')}

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

      ${d.structuredData?.length ? card('Structured data (schema.org)', html`
        ${d.structuredData.map((e) => html`
          <h4 class="rrtype">${e.legalName ?? e.name ?? 'Organisation'} <span class="pill">${e.type}</span></h4>
          ${dl([
            ['Legal name', e.legalName],
            ['Address', e.address],
            ['Telephone', e.telephone ? internalPivot('phone', e.telephone) : null],
            ['Email', e.email ? internalPivot('email', e.email) : null],
            ['Founded', e.foundingDate],
            ['Founders', e.founder?.length ? e.founder.join(', ') : null],
            ['Tax / VAT ID', e.taxId],
            ['Declared profiles', e.sameAs?.length
              ? html`<ul class="record-list compact">${e.sameAs.map((u) => html`<li><a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a></li>`)}</ul>`
              : null],
          ])}
        `)}
        <p class="note">Published by the site itself in a machine-readable field whose purpose is to state the
          legal entity. Self-declared, but far more reliable than anything scraped out of prose — and
          <code>sameAs</code> is the operator's own list of which profiles are theirs.</p>
      `, { wide: true }) : raw('')}

      ${d.providers ? card('Who runs what', dl([
        ['Mail', d.providers.mail ?? (d.providers.mailServers?.length ? html`<span class="muted">unrecognised</span>` : null)],
        ['Mail servers', d.providers.mailServers?.length ? html`<span class="mono tiny">${d.providers.mailServers.join(', ')}</span>` : null],
        ['DNS', d.providers.dns],
        ['Nameservers', d.providers.nameservers?.length ? html`<span class="mono tiny">${d.providers.nameservers.join(', ')}</span>` : null],
        ['CDN / edge', d.providers.cdn],
        ['Registrar', d.providers.registrar],
        ['Sending platforms', d.providers.sendingPlatforms?.length
          ? html`<div class="tags">${d.providers.sendingPlatforms.map((p) => html`<span class="tag">${p}</span>`)}</div>` : null],
        ['DMARC reporting', d.providers.dmarcReporting?.length ? d.providers.dmarcReporting.join(', ') : null],
      ])) : raw('')}

      ${d.page ? card('Site', dl([
        ['Title', d.page.title],
        ['Description', d.page.description],
        ['Site name', d.page.siteName],
        ['Author', d.page.author],
        ['Generator', d.page.generator ? html`<span class="pill">${d.page.generator}</span>` : null],
        ['Language', d.page.language],
        ['Twitter', d.page.twitterSite],
        ['App listing', d.page.appleApp ?? d.page.androidApp],
        ['Published numbers', d.page.phones?.length ? pivotChips('phone', d.page.phones) : null],
      ])) : raw('')}

      ${d.technologies?.length ? card('Technology', html`
        ${[...new Set(d.technologies.map((t) => t.category))].map((category) => html`
          <h4 class="rrtype">${category}</h4>
          <div class="tags spaced">
            ${d.technologies.filter((t) => t.category === category)
              .map((t) => html`<span class="tag" title="${t.evidence}">${t.name}</span>`)}
          </div>
        `)}
        <p class="note">Fingerprinted from response headers, cookie names and page source. Nothing was probed —
          every signal came from the one request already made to read the page.</p>
      `, { wide: true, count: d.technologies.length }) : raw('')}

      ${d.favicon ? card('Favicon hash', html`
        ${dl([
          ['MurmurHash3', html`<span class="mono">${d.favicon.hash}</span>`],
          ['Size', `${d.favicon.bytes.toLocaleString()} bytes`],
          ['Shodan query', html`<span class="mono">${d.favicon.shodanQuery}</span>`],
          ['FOFA query', html`<span class="mono">${d.favicon.fofaQuery}</span>`],
          ['Search', html`<a href="${d.favicon.shodanUrl}" target="_blank" rel="noopener noreferrer">Run it on Shodan</a>`],
        ])}
        <p class="note">${d.favicon.note}</p>
      `) : raw('')}

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
              <td>${internalPivot('ip', h.address)}</td>
              <td>${h.flag ?? ''} ${[h.city, h.country].filter(Boolean).join(', ') || '—'}</td>
              <td>${h.organization ?? '—'}${h.asn ? html` <span class="muted">${h.asn}</span>` : ''}</td>
              <td class="mono">${h.ports.length ? h.ports.join(', ') : '—'}</td>
            </tr>
          `)}</tbody>
        </table></div>
      `, { wide: true, count: d.hosting.length }) : raw('')}

      ${d.subdomainDetail?.takeoverCandidates?.length ? card('Possible subdomain takeovers', html`
        <div class="scroll"><table>
          <thead><tr><th>Subdomain</th><th>Points at</th><th>Service</th></tr></thead>
          <tbody>${d.subdomainDetail.takeoverCandidates.map((t) => html`
            <tr><td class="mono">${t.name}</td><td class="mono">${t.cname}</td><td>${t.service}</td></tr>`)}</tbody>
        </table></div>
        <p class="note">${d.subdomainDetail.takeoverCandidates[0].note}</p>
      `, { wide: true, count: d.subdomainDetail.takeoverCandidates.length }) : raw('')}

      ${d.subdomainDetail?.groups?.length ? card('Subdomain map', html`
        <div class="scroll"><table>
          <thead><tr><th>Address</th><th>Names</th></tr></thead>
          <tbody>${d.subdomainDetail.groups.map((g) => html`
            <tr>
              <td>${internalPivot('ip', g.address)}</td>
              <td class="mono tiny">${g.names.join(', ')}</td>
            </tr>`)}</tbody>
        </table></div>
        ${d.subdomainDetail.originCandidates?.length ? html`
          <h4 class="rrtype">Outside the apex's address set</h4>
          <div class="scroll"><ul class="record-list compact">
            ${d.subdomainDetail.originCandidates.map((o) => html`<li><span class="mono">${o.address}</span> <span class="muted">${o.names.join(', ')}</span></li>`)}
          </ul></div>
          <p class="note">These names resolve somewhere the apex does not. Behind a CDN, addresses like these are
            how the protection gets bypassed — they are the un-fronted hosts.</p>` : ''}
        <p class="note">${d.subdomainDetail.checked} of ${d.subdomainDetail.discovered} discovered names were
          resolved, chosen by how likely the prefix is to front something interesting.</p>
      `, { wide: true, count: d.subdomainDetail.live?.length }) : raw('')}

      ${d.subdomains?.length ? card('Subdomains', html`
        <div class="scroll">${pivotChips('domain', d.subdomains, { limit: 150 })}</div>
        ${d.certificates?.discoverySources?.length ? html`
          <p class="note">
            From ${d.certificates.discoverySources.map((s) => `${s.name} (${s.found})`).join(', ')}.
            Names appear in public logs; some may no longer resolve.
          </p>` : ''}
      `, { wide: true, count: d.subdomains.length }) : raw('')}

      ${d.relatedDomains?.length ? card('Domains sharing a certificate', html`
        ${pivotChips('domain', d.relatedDomains, { limit: 40 })}
        <p class="note">These appeared as names on a TLS certificate that also covers this domain. A certificate
          covering two domains was issued to whoever proved control of both, which makes this one of the
          strongest ownership links available from public logs.</p>
      `, { wide: true, count: d.relatedDomains.length }) : raw('')}

      ${d.dkim?.found?.length ? card('DKIM selectors', html`
        <div class="scroll"><table>
          <thead><tr><th>Selector</th><th>Platform</th><th>Key</th></tr></thead>
          <tbody>${d.dkim.found.map((f) => html`
            <tr>
              <td class="mono">${f.selector}</td>
              <td>${f.platform}</td>
              <td>${f.revoked ? html`<span class="pill warn">revoked</span>`
                : html`<span class="pill ${f.keyBits < 1024 ? 'bad' : 'good'}">${f.keyBits}-bit ${f.keyType}</span>`}</td>
            </tr>`)}</tbody>
        </table></div>
        <p class="note">${d.dkim.checked} conventional selectors were checked. Each one that resolves is a service
          authorised to send mail as this domain — several of these appear nowhere else in DNS.</p>
      `, { wide: true, count: d.dkim.found.length }) : raw('')}

      ${d.services?.found?.length ? card('SRV services', html`
        <div class="scroll"><table>
          <thead><tr><th>Service</th><th>Target</th><th>Port</th></tr></thead>
          <tbody>${d.services.found.map((s) => html`
            <tr><td>${s.service}</td><td class="mono">${s.target}</td><td class="mono">${s.port ?? '—'}</td></tr>`)}</tbody>
        </table></div>
        <p class="note">SRV targets name internal hosts that the apex's own records never expose.</p>
      `, { wide: true, count: d.services.found.length }) : raw('')}

      ${d.publicFiles?.files?.length ? card('Published files', html`
        ${d.publicFiles.files.map((f) => html`
          <h4 class="rrtype">${f.label} <span class="pill">${f.kind}</span></h4>
          ${f.disallowed?.length ? html`
            <p class="note">${f.disallowedCount} disallowed path(s):</p>
            <div class="tags spaced">${f.disallowed.slice(0, 30).map((p) => html`<span class="tag">${p}</span>`)}</div>` : ''}
          ${f.sitemaps?.length ? html`
            <p class="note">Sitemaps: ${f.sitemaps.map((s) => html`<a href="${s}" target="_blank" rel="noopener noreferrer">${s}</a> `)}</p>` : ''}
          ${f.directAccounts?.length ? html`
            <p class="note">${f.sellerCount} seller entries, ${f.directAccounts.length} of them DIRECT:</p>
            <div class="tags spaced">${f.directAccounts.map((a) => html`<span class="tag">${a}</span>`)}</div>
            <p class="note">A DIRECT account belongs to this site's owner, so the same ID on another site is a
              hard ownership link between them.</p>` : ''}
          ${f.excerpt ? html`<p class="rawvalue">${f.excerpt}</p>` : ''}
        `)}
      `, { wide: true, count: d.publicFiles.files.length }) : raw('')}

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

      ${d.lookalikes ? card('Lookalike domains', d.lookalikes.registered.length ? html`
        <div class="scroll"><table>
          <thead><tr><th>Domain</th><th>Technique</th><th>Resolves to</th></tr></thead>
          <tbody>${d.lookalikes.registered.map((l) => html`
            <tr>
              <td class="mono">${l.domain}</td>
              <td>${l.technique}</td>
              <td class="mono">${l.addresses.join(', ')}</td>
            </tr>`)}</tbody>
        </table></div>
        <p class="note">${d.lookalikes.note} Registration alone is not proof of abuse, but these are the names a phishing
          operator would reach for. Only a bounded subset is resolved, so a clean result is not a guarantee.</p>
      ` : html`<p class="muted">None of the permutations checked are registered.</p>
        <p class="note">${d.lookalikes.note}</p>`,
        { wide: d.lookalikes.registered.length > 0, count: d.lookalikes.registered.length }) : raw('')}

      ${d.scans?.results?.length ? card('urlscan.io history', html`
        <div class="scroll"><table>
          <thead><tr><th>Scanned</th><th>Title</th><th>Address</th><th>Server</th></tr></thead>
          <tbody>${d.scans.results.map((r) => html`
            <tr>
              <td>${r.reportUrl ? html`<a href="${r.reportUrl}" target="_blank" rel="noopener noreferrer">${formatDate(r.scannedAt) ?? '—'}</a>` : formatDate(r.scannedAt) ?? '—'}</td>
              <td>${r.title ?? '—'}</td>
              <td class="mono">${r.address ?? '—'}</td>
              <td>${r.server ?? '—'}</td>
            </tr>`)}</tbody>
        </table></div>
        <p class="note">${d.scans.total} public scan(s) on record. Addresses observed here can differ from what the domain
          resolves to now, which is useful for spotting infrastructure moves.</p>
      `, { wide: true, count: d.scans.total }) : raw('')}

      ${d.redirectChain?.length > 1 ? card('Redirect chain', html`
        <ol class="record-list chain">
          ${d.redirectChain.map((hop) => html`<li>
            <span class="pill ${hop.status >= 300 && hop.status < 400 ? 'warn' : 'good'}">${hop.status}</span>
            <span class="mono">${hop.url}</span>
          </li>`)}
        </ol>
        <p class="note">The route the site takes before serving content. Redirects to a different registrable
          domain are worth explaining — that is the shape of an affiliate hop, a parked domain, or a hijack.</p>
      `, { wide: true, count: d.redirectChain.length }) : raw('')}

      ${d.wildcard?.wildcard ? card('Wildcard DNS', html`
        <p class="note">A random name (<span class="mono">${d.wildcard.probe}</span>) resolved to
          <span class="mono">${d.wildcard.addresses.join(', ')}</span>. ${d.wildcard.note}</p>
      `, { wide: true }) : raw('')}

      ${d.dnssec ? card('DNSSEC', dl([
        ['Delegation signed', d.dnssec.delegationSigned === true ? html`<span class="pill good">yes</span>`
          : d.dnssec.delegationSigned === false ? html`<span class="pill">no</span>` : null],
        ['DS records', d.dnssec.dsRecords],
        ['DNSKEY records', d.dnssec.dnskeyRecords],
        ['Algorithms', d.dnssec.algorithms?.length ? d.dnssec.algorithms.join(', ') : null],
        ['Signed but not delegated', d.dnssec.signedButNotDelegated ? html`<span class="pill bad">yes</span>` : null],
      ])) : raw('')}

      ${d.httpHeaders ? card('HTTP response', dl([
        ['Status', d.httpHeaders.status],
        ['Final URL', d.httpHeaders.finalUrl],
        ['Server', d.httpHeaders.server],
        ['CDN', d.httpHeaders.cdn],
        ['Cookies', d.httpHeaders.cookieNames?.length
          ? html`<span class="mono tiny">${d.httpHeaders.cookieNames.join(', ')}</span>` : null],
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

/**
 * Run a lookup on an entity discovered in the current report.
 *
 * The mode switch and the input are updated too, so the app's visible state
 * matches what is on screen and the back-forward history stays coherent.
 */
function onInternalPivot(event) {
  const button = event.target.closest('[data-lookup-type]');
  if (!button) return;

  const { lookupType, lookupValue } = button.dataset;
  if (!MODES[lookupType]) return;

  setMode(lookupType, { focus: false });
  $('#query').value = lookupValue;
  $('#clearBtn').hidden = false;
  scrollTo({ top: 0, behavior: 'smooth' });
  runLookup(lookupValue, '');
}

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
    section('Numbering plan (LERG)', [
      ['Rate centre', d.numberingPlan?.rateCentre], ['Region', d.numberingPlan?.region],
      ['Switch', d.numberingPlan?.switchClli], ['Switch name', d.numberingPlan?.switchName],
      ['Block holder', d.numberingPlan?.company], ['OCN', d.numberingPlan?.ocn],
      ['Carrier type', d.numberingPlan?.companyType], ['LATA', d.numberingPlan?.lata],
      ['Wholesale carrier', d.numberingPlan?.wholesaleCarrier],
    ]);
    section('Risk profile', [
      ['Level', d.riskProfile?.level],
      ['Signals', d.riskProfile?.signals?.map((s) => `${s.signal}: ${s.detail}`)],
    ]);
    section('Attribution', [
      ['Best match', d.attribution?.best ? `${d.attribution.best.value} (${d.attribution.best.source}, ${d.attribution.best.confidence} confidence)` : null],
      ['All candidates', d.attribution?.names?.map((n) => `${n.value} — ${n.source}, ${n.confidence}`)],
      ['Sources checked', d.attribution?.checked],
    ]);
    if (d.filings?.companies?.length) {
      lines.push('## SEC filings', '',
        ...d.filings.companies.map((c) => `- **${c.name}** (${c.confirmed ? 'filed' : 'mentioned'})${c.phone ? ` — ${c.phone}` : ''}${c.location ? ` — ${c.location}` : ''}`), '');
    }
    if (d.search?.results?.length) {
      lines.push('## Search footprint', '',
        ...d.search.results.map((r) => `- [${r.title ?? r.url}](${r.url})`), '');
    }
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
    section('Classification', [
      ['Kind', d.classification?.kind], ['Operator', d.classification?.operator],
      ['Meaning', d.classification?.meaning],
      ['Evidence', d.classification?.evidence?.map((e) => `${e.signal}: ${e.detail}`)],
    ]);
    section('Geolocation', [
      ['Country', d.geolocation?.country], ['Region', d.geolocation?.region], ['City', d.geolocation?.city],
      ['Precision', d.geolocation?.precision], ['Coordinates', d.geolocation?.latitude != null
        ? `${d.geolocation.latitude}, ${d.geolocation.longitude}` : null],
      ['Provider agreement', d.geolocationAgreement?.verdict],
      ['Widest disagreement', d.geolocationAgreement?.spreadKm != null ? `${d.geolocationAgreement.spreadKm} km` : null],
    ]);
    section('Operator geofeed (RFC 8805)', [
      ['Prefix', d.geofeed?.prefix], ['Country', d.geofeed?.country],
      ['Region', d.geofeed?.region], ['City', d.geofeed?.city], ['Source', d.geofeed?.source],
    ]);
    section('Network', [
      ['Organisation', d.geolocation?.organization], ['ASN', d.geolocation?.asn],
      ['Reverse DNS', d.reverseDns],
      ['PTR platform', d.reverseDnsIntel?.platform], ['PTR region', d.reverseDnsIntel?.region],
      ['Netblock', d.registry?.cidr ?? d.registry?.range],
      ['RIR allocation', d.allocation?.allocatedPrefix],
      ['Allocated', d.allocation?.allocationDate],
      ['Abuse contact', d.registry?.abuseContact?.email],
      ['Escalation path', d.abuseContacts?.emails],
      ['Announced prefix', d.routing?.announcedPrefix],
      ['Origin AS', d.routing?.originAsns?.map((a) => `${a.asn}${a.holder ? ` (${a.holder})` : ''}`)],
    ]);
    section('Blocklists', [
      ['Listed on', d.blocklists?.listedOn],
      ['Zones usable', d.blocklists?.usable],
      ['Listings', d.blocklists?.listings?.map((l) => `${l.name}: ${l.reasons.join('; ')}`)],
    ]);
    if (d.anonymity?.tor) {
      section('Tor relay', [
        ['Nickname', d.anonymity.relay?.nickname], ['Flags', d.anonymity.relay?.flags],
        ['Exit relay', d.anonymity.relay?.isExit], ['Contact', d.anonymity.relay?.contact],
      ]);
    }
    if (d.routingHistory?.origins?.length) {
      lines.push('## Routing history', '',
        ...d.routingHistory.origins.map((o) => `- ${o.asn} — ${o.firstSeen ?? '?'} → ${o.lastSeen ?? 'current'}`), '');
    }
    if (d.hostedDomains?.count) {
      lines.push(`## Domains on this address (${d.hostedDomains.count})`, '',
        ...d.hostedDomains.domains.map((n) => `- ${n}`), '');
    }
    section('Exposure', [
      ['Open ports', d.exposure?.ports], ['Known CVEs', d.exposure?.vulnerabilities],
      ['Hostnames', d.exposure?.hostnames],
    ]);
    section('Attack history', [
      ['Networks attacked', d.threat?.targets], ['Events logged', d.threat?.records],
      ['First seen', d.threat?.firstSeen], ['Last seen', d.threat?.lastSeen],
      ['Threat feeds', d.threat?.threatFeeds],
    ]);
    section('Network operator', [
      ['Name', d.network?.name], ['Type', d.network?.networkType],
      ['Scope', d.network?.scope], ['Peering policy', d.network?.peeringPolicy],
      ['IRR AS-SET', d.network?.irrAsSet],
    ]);
  } else if (d.query.type === 'email') {
    section('Address', [
      ['Kind', d.classification?.kind], ['Meaning', d.classification?.meaning],
      ['Domain', d.address?.domain], ['Canonical', d.address?.canonical],
      ['Sub-address tag', d.classification?.subAddressTag],
      ['Likely typo for', d.classification?.likelyTypo],
      ['SHA-256', d.address?.sha256], ['MD5', d.address?.md5],
    ]);
    section('Gravatar', [
      ['Exists', d.gravatar?.exists], ['Name', d.gravatar?.name],
      ['Display name', d.gravatar?.displayName], ['Username', d.gravatar?.username],
      ['Location', d.gravatar?.location], ['Company', d.gravatar?.company],
      ['Bio', d.gravatar?.aboutMe], ['Profile', d.gravatar?.profileUrl],
    ]);
    if (d.identity?.accounts?.length) {
      lines.push('## Linked accounts', '',
        ...d.identity.accounts.map((a) => `- **${a.platform}** ${a.username ?? ''} — ${a.verified ? 'verified' : 'unconfirmed'} (${a.source})${a.url ? ` — ${a.url}` : ''}`), '');
    }
    section('Mail', [
      ['Deliverable', d.mail?.deliverable], ['Null MX', d.mail?.nullMx],
      ['Provider', d.mail?.provider], ['MX hosts', d.mail?.mxHosts?.map((h) => h.host)],
      ['SPF', d.mail?.spf], ['DMARC policy', d.mail?.dmarcPolicy],
    ]);
    section('Domain registration', [
      ['Domain', d.domainRegistration?.domain], ['Created', d.domainRegistration?.created],
      ['Age (days)', d.domainRegistration?.ageDays], ['Registrar', d.domainRegistration?.registrar],
    ]);
    if (d.breaches?.breached) {
      lines.push('## Breaches', '',
        ...d.breaches.breaches.map((b) => `- **${b.name}** (${b.date ?? '?'}) — ${(b.data ?? []).join(', ')}`), '');
    }
    section('Leads', [
      ['Username candidates', d.usernameCandidates],
    ]);
    if (d.caveats?.length) lines.push('## Caveats', '', ...d.caveats.map((c) => `- ${c}`), '');
  } else if (d.query.type === 'username') {
    section('Summary', [
      ['Checked', d.summary?.checked], ['Found', d.summary?.found],
      ['Not found', d.summary?.absent], ['Could not check', d.summary?.unavailable],
      ['Best name', d.identity?.bestName],
      ['Corroborating platforms', d.identity?.corroboration],
      ['Earliest account', d.identity?.earliest ? `${d.identity.earliest.joined} on ${d.identity.earliest.platform}` : null],
    ]);
    if (d.accounts?.length) {
      lines.push('## Accounts found', '');
      for (const a of d.accounts) {
        lines.push(`### ${a.platform}`, '', `- **URL:** ${a.url}`);
        for (const [label, value] of [['Name', a.displayName], ['Bio', a.bio], ['Location', a.location],
          ['Company', a.company], ['Email', a.email], ['Website', a.website], ['Joined', a.joined]]) {
          if (value) lines.push(`- **${label}:** ${value}`);
        }
        lines.push('');
      }
    }
    section('Correlation', [
      ['Names', d.identity?.names?.map((n) => `${n.value} (${n.sources.join(', ')})`)],
      ['Locations', d.identity?.locations?.map((l) => `${l.value} (${l.sources.join(', ')})`)],
      ['Emails', d.identity?.emails?.map((e) => e.value)],
      ['Declared handles', d.identity?.declaredHandles?.map((h) => `${h.platform}:${h.username} (${h.proof}, via ${h.via})`)],
      ['Published links', d.identity?.links?.map((l) => l.url)],
    ]);
    section('Not checked', [
      ['Unavailable', d.unavailable?.map((u) => `${u.platform} — ${u.error}`)],
      ['Manual only', d.manualChecks?.map((m) => `${m.platform} — ${m.reason}`)],
    ]);
    if (d.caveats?.length) lines.push('## Caveats', '', ...d.caveats.map((c) => `- ${c}`), '');
  } else if (d.query.type === 'asn') {
    section('Network', [
      ['Name', d.profile?.name ?? d.overview?.holder], ['Description', d.profile?.description],
      ['Country', d.profile?.country], ['RIR', d.profile?.rir],
      ['Allocated', d.profile?.allocated], ['Announced', d.overview?.announced],
      ['Website', d.profile?.website], ['Registered address', d.profile?.ownerAddress],
    ]);
    section('Registry', [
      ['Handle', d.registry?.handle], ['Holder', d.registry?.registrant?.organization ?? d.registry?.registrant?.name],
      ['Registered', d.registry?.registered], ['Updated', d.registry?.updated],
    ]);
    section('Contacts', [
      ['Published', d.contacts?.map((c) => `${c.role}: ${c.value} (${c.source})`)],
    ]);
    section('Prefixes', [
      ['IPv4 prefixes', d.prefixes?.ipv4Count], ['IPv6 prefixes', d.prefixes?.ipv6Count],
      ['IPv4 addresses', d.prefixes?.ipv4Addresses?.toLocaleString()],
    ]);
    if (d.prefixes?.ipv4?.length) {
      lines.push('## Announced IPv4 prefixes', '', ...d.prefixes.ipv4.map((p) => `- ${p.prefix}${p.description ? ` — ${p.description}` : ''}`), '');
    }
    section('Relationships', [
      ['Upstreams', d.upstreams?.networks?.map((u) => `${u.asn} ${u.name ?? ''}`.trim())],
      ['Peer count', d.peers?.count],
      ['Exchanges', d.exchanges?.exchanges?.map((x) => `${x.name} (${x.city ?? ''}, ${x.country ?? ''})`)],
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
      ['Published numbers', d.page?.phones],
    ]);
    if (d.structuredData?.length) {
      lines.push('## Structured data (schema.org)', '');
      for (const e of d.structuredData) {
        lines.push(`### ${e.legalName ?? e.name ?? e.type}`, '');
        for (const [label, value] of [['Type', e.type], ['Legal name', e.legalName], ['Address', e.address],
          ['Telephone', e.telephone], ['Email', e.email], ['Founded', e.foundingDate],
          ['Founders', e.founder?.join(', ')], ['Tax ID', e.taxId], ['Declared profiles', e.sameAs?.join(', ')]]) {
          if (value) lines.push(`- **${label}:** ${value}`);
        }
        lines.push('');
      }
    }
    section('Infrastructure providers', [
      ['Mail', d.providers?.mail], ['DNS', d.providers?.dns], ['CDN', d.providers?.cdn],
      ['Registrar', d.providers?.registrar],
      ['Sending platforms', d.providers?.sendingPlatforms],
    ]);
    section('Technology', [
      ['Detected', d.technologies?.map((t) => `${t.name} (${t.category})`)],
    ]);
    section('Favicon', [
      ['MurmurHash3', d.favicon?.hash], ['Shodan query', d.favicon?.shodanQuery],
    ]);
    section('DKIM selectors', [
      ['Found', d.dkim?.found?.map((f) => `${f.selector} — ${f.platform}${f.revoked ? ' (revoked)' : `, ${f.keyBits}-bit`}`)],
    ]);
    section('SRV services', [
      ['Found', d.services?.found?.map((s) => `${s.service} → ${s.target}:${s.port}`)],
    ]);
    if (d.subdomainDetail?.takeoverCandidates?.length) {
      lines.push('## Possible subdomain takeovers', '',
        ...d.subdomainDetail.takeoverCandidates.map((t) => `- ${t.name} → ${t.cname} (${t.service})`), '');
    }
    if (d.subdomainDetail?.originCandidates?.length) {
      lines.push('## Addresses outside the apex set', '',
        ...d.subdomainDetail.originCandidates.map((o) => `- ${o.address} — ${o.names.join(', ')}`), '');
    }
    if (d.relatedDomains?.length) {
      lines.push('## Domains sharing a certificate', '', ...d.relatedDomains.map((r) => `- ${r}`), '');
    }
    if (d.redirectChain?.length > 1) {
      lines.push('## Redirect chain', '', ...d.redirectChain.map((h) => `- ${h.status} ${h.url}`), '');
    }
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
    if (d.lookalikes?.registered?.length) {
      lines.push('## Registered lookalike domains', '',
        ...d.lookalikes.registered.map((l) => `- ${l.domain} (${l.technique}) -> ${l.addresses.join(', ')}`),
        '', `_${d.lookalikes.note}_`, '');
    }
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
  initDepth();
  initRegions();
  renderHistory();

  // Six modes no longer fit the hardcoded three-column grid, so the count
  // drives the layout and the glider width from one place.
  document.documentElement.style.setProperty('--mode-count', String(Object.keys(MODES).length));

  document.querySelectorAll('.mode').forEach((button) => {
    button.addEventListener('click', () => setMode(button.dataset.mode));
  });

  // Delegated once: #results is replaced wholesale on every render.
  $('#results').addEventListener('click', onResultAction);
  $('#results').addEventListener('click', onInternalPivot);

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
