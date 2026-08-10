/**
 * Input validation and normalization.
 *
 * The API surface is a proxy to third-party services, so every value that ends
 * up in an upstream URL is validated against a strict grammar first. Nothing
 * user-supplied is interpolated before passing through here.
 */

export class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
  }
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

const HEX_GROUP = /^[0-9a-f]{1,4}$/i;

/**
 * Validate an IPv6 address.
 *
 * Written out rather than done with a regex: the `::` compression rule needs
 * a group count, and every "one-line IPv6 regex" either backtracks wrongly on
 * addresses like 2606:4700:4700::1111 or accepts nonsense. Supports the
 * dotted-quad tail form (::ffff:192.0.2.1).
 */
function isIpv6(value) {
  if (value === '::') return true;
  if ((value.match(/::/g) ?? []).length > 1) return false;
  if (/:::/.test(value)) return false;

  const compressed = value.includes('::');
  const [head, tail = ''] = compressed ? value.split('::') : [value];

  const headGroups = head ? head.split(':') : [];
  const tailGroups = tail ? tail.split(':') : [];
  const groups = [...headGroups, ...tailGroups];
  if (groups.some((g) => g === '')) return false;

  // A trailing dotted quad occupies the last two 16-bit groups.
  let width = groups.length;
  const last = groups[groups.length - 1];
  if (last?.includes('.')) {
    const octets = last.match(IPV4);
    if (!octets || octets.slice(1).some((o) => Number(o) > 255)) return false;
    groups.pop();
    width += 1;
  }

  if (groups.some((g) => !HEX_GROUP.test(g))) return false;
  return compressed ? width < 8 : width === 8;
}

/**
 * Hostname label grammar: 1-63 chars, alphanumeric with internal hyphens.
 * Allows leading `_` for service labels such as `_dmarc` and `_domainkey`.
 */
const LABEL = /^_?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

/** RFC 1918, loopback, link-local and CGNAT ranges — not publicly routable. */
function classifyIpv4(octets) {
  const [a, b] = octets;
  if (a === 10) return 'private';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 127) return 'loopback';
  if (a === 169 && b === 254) return 'link-local';
  if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
  if (a === 0 || a >= 224) return 'reserved';
  return 'public';
}

/**
 * Validate an IP address.
 * @returns {{value: string, version: 4|6, scope: string}}
 */
export function parseIp(input) {
  const value = String(input ?? '').trim().toLowerCase();
  if (!value) throw new ValidationError('An IP address is required.');

  const v4 = value.match(IPV4);
  if (v4) {
    const octets = v4.slice(1).map(Number);
    if (octets.some((o) => o > 255)) {
      throw new ValidationError(`"${value}" is not a valid IPv4 address — octets must be 0-255.`);
    }
    // Reject zero-padded forms; they are parsed as octal by some resolvers.
    if (v4.slice(1).some((o) => o.length > 1 && o.startsWith('0'))) {
      throw new ValidationError(`"${value}" has zero-padded octets, which are ambiguous.`);
    }
    return { value: octets.join('.'), version: 4, scope: classifyIpv4(octets) };
  }

  if (isIpv6(value)) {
    const scope =
      value === '::1' ? 'loopback'
      : value.startsWith('fe80') ? 'link-local'
      : /^f[cd]/.test(value) ? 'private'
      : 'public';
    return { value, version: 6, scope };
  }

  throw new ValidationError(`"${input}" is not a valid IPv4 or IPv6 address.`);
}

/**
 * Validate and normalize a domain name. Accepts a bare domain or a full URL and
 * reduces both to a registrable hostname.
 * @returns {{value: string, labels: string[], tld: string}}
 */
export function parseDomain(input) {
  let raw = String(input ?? '').trim().toLowerCase();
  if (!raw) throw new ValidationError('A domain name is required.');

  // Accept pasted URLs: strip scheme, credentials, port, path, query and fragment.
  raw = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  raw = raw.split('@').pop();
  raw = raw.split(/[/?#]/)[0];
  raw = raw.split(':')[0];
  raw = raw.replace(/\.$/, ''); // trailing root dot

  if (!raw) throw new ValidationError(`Could not extract a hostname from "${input}".`);
  if (raw.length > 253) throw new ValidationError('Domain names cannot exceed 253 characters.');

  const labels = raw.split('.');
  if (labels.length < 2) {
    throw new ValidationError(`"${raw}" is not a fully-qualified domain — it needs at least one dot.`);
  }
  for (const label of labels) {
    if (!LABEL.test(label)) {
      throw new ValidationError(`"${raw}" contains an invalid label: "${label}".`);
    }
  }

  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/.test(tld) && !tld.startsWith('xn--')) {
    throw new ValidationError(`"${tld}" is not a valid top-level domain.`);
  }

  return { value: raw, labels, tld };
}

/**
 * Light pre-validation for phone input. Full parsing is libphonenumber's job;
 * this only guards the shape before we hand it over.
 * @returns {{value: string, region: string|undefined}}
 */
export function parsePhoneInput(input, region) {
  const value = String(input ?? '').trim();
  if (!value) throw new ValidationError('A phone number is required.');
  if (value.length > 32) throw new ValidationError('That phone number is implausibly long.');
  if (!/[0-9]/.test(value)) throw new ValidationError('A phone number must contain digits.');
  if (!/^[+()\d\s.\-/]+$/.test(value)) {
    throw new ValidationError('Phone numbers may only contain digits and the symbols + ( ) - . / and spaces.');
  }

  let normalizedRegion;
  if (region) {
    normalizedRegion = String(region).trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(normalizedRegion)) {
      throw new ValidationError('Region must be a two-letter ISO country code, e.g. US or GB.');
    }
  }

  return { value, region: normalizedRegion };
}

/**
 * Validate an email address.
 *
 * Deliberately not RFC 5322-complete: the full grammar permits quoted local
 * parts, comments and nested folding whitespace that no real mailbox uses and
 * that no upstream here would accept. This checks the shape every deliverable
 * address actually has, and reuses the domain grammar for the right-hand side
 * so an address and a domain lookup agree on what a hostname is.
 *
 * @returns {{value: string, local: string, domain: string, tag: string|null,
 *            canonical: string, labels: string[]}}
 */
export function parseEmail(input) {
  const raw = String(input ?? '').trim().replace(/^mailto:/i, '');
  if (!raw) throw new ValidationError('An email address is required.');
  if (raw.length > 254) throw new ValidationError('Email addresses cannot exceed 254 characters.');

  const at = raw.lastIndexOf('@');
  if (at < 1 || at === raw.length - 1) {
    throw new ValidationError(`"${input}" is not an email address — it needs a local part and a domain either side of an "@".`);
  }

  const local = raw.slice(0, at);
  const domainPart = raw.slice(at + 1).toLowerCase();

  if (local.length > 64) throw new ValidationError('The local part of an email address cannot exceed 64 characters.');
  if (!/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local)) {
    throw new ValidationError(`"${local}" contains characters that are not valid in an email local part.`);
  }
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) {
    throw new ValidationError('The local part cannot start or end with a dot, or contain two in a row.');
  }

  const domain = parseDomain(domainPart);

  // The sub-address tag ("+newsletter") is chosen per-signup, so it frequently
  // records where the address was given out — worth isolating rather than
  // discarding.
  const plus = local.indexOf('+');
  const tag = plus > 0 ? local.slice(plus + 1) : null;
  const base = plus > 0 ? local.slice(0, plus) : local;

  // Gmail ignores dots and everything after a "+", so several written forms are
  // one mailbox. Canonicalising means a Gravatar or breach lookup finds the
  // account even when the address was written in a variant spelling.
  const gmail = domain.value === 'gmail.com' || domain.value === 'googlemail.com';
  const canonical = gmail
    ? `${base.replace(/\./g, '').toLowerCase()}@gmail.com`
    : `${base.toLowerCase()}@${domain.value}`;

  return {
    value: `${local}@${domain.value}`,
    local,
    domain: domain.value,
    labels: domain.labels,
    tag,
    canonical,
  };
}

/**
 * Validate a username / handle.
 *
 * The union of what the platforms checked will accept: letters, digits, and the
 * three separators between them. Anything else is either a different kind of
 * identifier or an injection attempt, and either way is not a username.
 *
 * @returns {{value: string}}
 */
export function parseUsername(input) {
  let value = String(input ?? '').trim();
  if (!value) throw new ValidationError('A username is required.');

  // Accept the forms people paste: @handle, a profile URL, user@instance.
  value = value.replace(/^@+/, '');
  if (/^https?:\/\//i.test(value)) {
    const path = value.replace(/^https?:\/\/[^/]+\//i, '').split(/[/?#]/)[0];
    value = path.replace(/^@+/, '') || value;
  }
  value = value.split('@')[0];

  if (value.length < 2) throw new ValidationError('Usernames must be at least 2 characters.');
  if (value.length > 39) throw new ValidationError('That is longer than any of the platforms checked allow (39 characters).');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) {
    throw new ValidationError('Usernames may only contain letters, digits, and the separators . _ and -, and must start with a letter or digit.');
  }

  return { value };
}

/**
 * Validate an autonomous system number.
 * Accepts "AS15169", "as15169", "15169" and the 32-bit range.
 *
 * @returns {{value: number, label: string}}
 */
export function parseAsn(input) {
  const raw = String(input ?? '').trim().toUpperCase().replace(/^AS/, '');
  if (!/^\d+$/.test(raw)) {
    throw new ValidationError(`"${input}" is not an AS number. Use a form like AS15169 or 15169.`);
  }

  const value = Number(raw);
  if (value < 0 || value > 4294967295) {
    throw new ValidationError('AS numbers run from 0 to 4294967295.');
  }
  if (value === 0 || (value >= 64496 && value <= 65551) || (value >= 4200000000)) {
    // Documentation and private ranges have no public registry record, so say
    // why the lookup will be empty instead of returning four upstream errors.
    return { value, label: `AS${value}`, reserved: true };
  }

  return { value, label: `AS${value}`, reserved: false };
}

/**
 * The registrable domain, best-effort without a full Public Suffix List.
 * Handles the common two-part public suffixes (co.uk, com.au, ...).
 */
export function registrableDomain(labels) {
  const twoPartSuffixes = new Set([
    'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'net.uk', 'sch.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz',
    'co.za', 'org.za', 'net.za',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'com.br', 'net.br', 'org.br', 'gov.br',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'co.in', 'net.in', 'org.in', 'gov.in',
    'com.mx', 'org.mx', 'gob.mx',
    'com.sg', 'com.hk', 'com.tw', 'com.tr', 'com.ar', 'com.pl',
  ]);

  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  if (twoPartSuffixes.has(lastTwo)) return labels.slice(-3).join('.');
  return lastTwo;
}
