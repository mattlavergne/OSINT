/**
 * Provider fingerprints and reference lists.
 *
 * Raw records — an MX hostname, a `Server` header, a CNAME target — name a
 * machine. What an investigator actually wants is the *organisation* behind it,
 * because that is what narrows a target: "mail is on Google Workspace" is a
 * different lead from "mail is on a self-hosted Postfix".
 *
 * Everything here is pattern → label. Kept in one module so the same knowledge
 * is shared by the domain, IP and email lookups instead of being re-derived
 * three times with three sets of gaps.
 */

/** Match a hostname or header against a [pattern, label] table. */
function matchTable(table, ...values) {
  const haystack = values.filter(Boolean).join(' ').toLowerCase();
  if (!haystack) return null;
  for (const [pattern, label] of table) {
    if (haystack.includes(pattern)) return label;
  }
  return null;
}

/* ------------------------------------------------------------------- email */

/**
 * MX hostname → mail provider.
 *
 * Ordered: the first match wins, so specific patterns precede generic ones
 * (`outlook.com` before `microsoft`).
 */
const MAIL_PROVIDERS = [
  ['aspmx.l.google.com', 'Google Workspace'],
  ['googlemail.com', 'Google Workspace'],
  ['google.com', 'Google Workspace'],
  ['mail.protection.outlook.com', 'Microsoft 365'],
  ['outlook.com', 'Microsoft 365'],
  ['protection.office365', 'Microsoft 365'],
  ['pphosted.com', 'Proofpoint'],
  ['ppe-hosted.com', 'Proofpoint Essentials'],
  ['mimecast', 'Mimecast'],
  ['barracudanetworks', 'Barracuda'],
  ['messagelabs.com', 'Broadcom / Symantec MessageLabs'],
  ['iphmx.com', 'Cisco Secure Email (IronPort)'],
  ['trendmicro', 'Trend Micro'],
  ['mx.cloudflare.net', 'Cloudflare Email Routing'],
  ['zoho', 'Zoho Mail'],
  ['protonmail', 'Proton Mail'],
  ['proton.me', 'Proton Mail'],
  ['fastmail', 'Fastmail'],
  ['messagingengine.com', 'Fastmail'],
  ['migadu', 'Migadu'],
  ['mailgun', 'Mailgun'],
  ['sendgrid', 'SendGrid'],
  ['amazonses.com', 'Amazon SES'],
  ['awsapps.com', 'Amazon WorkMail'],
  ['yandex', 'Yandex 360'],
  ['mail.ru', 'Mail.ru'],
  ['qq.com', 'Tencent Exmail'],
  ['aliyun', 'Alibaba Mail'],
  ['secureserver.net', 'GoDaddy'],
  ['registrar-servers.com', 'Namecheap Private Email'],
  ['ionos', 'IONOS'],
  ['ovh.net', 'OVH'],
  ['hostinger', 'Hostinger'],
  ['bluehost', 'Bluehost'],
  ['dreamhost', 'DreamHost'],
  ['siteground', 'SiteGround'],
  ['cpanel', 'cPanel (self-hosted)'],
  ['improvmx', 'ImprovMX (forwarding)'],
  ['forwardemail', 'Forward Email (forwarding)'],
  ['mxroute', 'MXroute'],
  ['titan.email', 'Titan'],
  ['hover.com', 'Hover'],
  ['emailsrvr.com', 'Rackspace Email'],
];

export const mailProvider = (...mx) => matchTable(MAIL_PROVIDERS, ...mx);

/**
 * Consumer mailbox providers. Distinguishing "a personal address" from "an
 * address at an organisation's own domain" changes what every other signal in
 * an email lookup means.
 */
export const FREE_MAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'rocketmail.com',
  'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 'passport.com',
  'aol.com', 'icloud.com', 'me.com', 'mac.com',
  'proton.me', 'protonmail.com', 'pm.me', 'tutanota.com', 'tuta.io',
  'zoho.com', 'zohomail.com', 'gmx.com', 'gmx.de', 'gmx.net', 'web.de',
  'mail.com', 'mail.ru', 'yandex.ru', 'yandex.com', 'inbox.ru', 'bk.ru', 'list.ru',
  'qq.com', '163.com', '126.com', 'sina.com', 'naver.com', 'daum.net',
  'fastmail.com', 'hey.com', 'hushmail.com', 'posteo.de', 'mailbox.org',
  'orange.fr', 'wanadoo.fr', 'free.fr', 'laposte.net', 'sfr.fr',
  't-online.de', 'libero.it', 'virgilio.it', 'terra.com.br', 'uol.com.br',
  'btinternet.com', 'sky.com', 'talktalk.net', 'blueyonder.co.uk',
  'comcast.net', 'verizon.net', 'att.net', 'sbcglobal.net', 'cox.net',
  'bellsouth.net', 'charter.net', 'shaw.ca', 'rogers.com', 'telus.net',
  'optonline.net', 'earthlink.net', 'juno.com', 'aim.com',
]);

/**
 * Disposable / throwaway mailbox domains.
 *
 * Not exhaustive — no static list can be, the services mint new domains daily —
 * but it covers the operators behind the overwhelming majority of throwaway
 * addresses, and a hit is a strong signal on its own.
 */
export const DISPOSABLE_MAIL_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.info', 'guerrillamail.net',
  'sharklasers.com', 'grr.la', 'spam4.me', 'pokemail.net',
  '10minutemail.com', '10minutemail.net', 'temp-mail.org', 'tempmail.com',
  'tempmailo.com', 'tempr.email', 'throwawaymail.com', 'trashmail.com',
  'trashmail.de', 'yopmail.com', 'yopmail.fr', 'jetable.org',
  'maildrop.cc', 'mailnesia.com', 'dispostable.com', 'fakeinbox.com',
  'getnada.com', 'nada.email', 'inboxkitten.com', 'emailondeck.com',
  'mohmal.com', 'mytemp.email', 'moakt.com', 'tmpmail.org', 'tmpmail.net',
  'burnermail.io', 'anonaddy.com', 'anonaddy.me', 'addy.io',
  'simplelogin.com', 'simplelogin.io', 'slmail.me', 'aleeas.com',
  'duck.com', 'relay.firefox.com', 'mozmail.com', 'icloud.com.relay',
  'spamgourmet.com', 'mailcatch.com', 'harakirimail.com', 'discard.email',
  'einrot.com', 'cuvox.de', 'dayrep.com', 'fleckens.hu', 'gustr.com',
  'jourrapide.com', 'rhyta.com', 'superrito.com', 'teleworm.us', 'armyspy.com',
  'byom.de', 'dropmail.me', 'mailtemp.net', 'linshiyouxiang.net',
]);

/**
 * Aliasing services worth calling out separately from throwaways: these are
 * used by privacy-conscious people for real, long-lived accounts, so treating
 * them as disposable produces the wrong conclusion.
 */
export const ALIAS_MAIL_DOMAINS = new Set([
  'anonaddy.com', 'anonaddy.me', 'addy.io', 'simplelogin.com', 'simplelogin.io',
  'slmail.me', 'aleeas.com', 'duck.com', 'relay.firefox.com', 'mozmail.com',
  'passinbox.com', 'passmail.net', 'hide-my-email',
]);

/** Shared-function mailboxes: a team, not a person. */
export const ROLE_LOCAL_PARTS = new Set([
  'admin', 'administrator', 'abuse', 'billing', 'contact', 'help', 'hello',
  'hi', 'hostmaster', 'info', 'inquiries', 'enquiries', 'it', 'jobs', 'legal',
  'mail', 'marketing', 'noc', 'noreply', 'no-reply', 'office', 'orders',
  'postmaster', 'privacy', 'root', 'sales', 'security', 'service', 'support',
  'sysadmin', 'team', 'webmaster', 'press', 'media', 'careers', 'hr',
  'accounts', 'accounting', 'finance', 'compliance', 'dpo', 'gdpr', 'newsletter',
]);

/**
 * Near-miss domains for the big consumer providers, so a typo is reported as a
 * typo rather than as a domain that simply has no MX.
 */
export const MAIL_TYPOS = {
  'gmial.com': 'gmail.com', 'gmai.com': 'gmail.com', 'gmail.co': 'gmail.com',
  'gmail.con': 'gmail.com', 'gmail.cm': 'gmail.com', 'gnail.com': 'gmail.com',
  'gmail.om': 'gmail.com', 'gamil.com': 'gmail.com', 'gmaill.com': 'gmail.com',
  'hotmial.com': 'hotmail.com', 'hotmai.com': 'hotmail.com', 'hotmal.com': 'hotmail.com',
  'hotmail.co': 'hotmail.com', 'homail.com': 'hotmail.com',
  'yaho.com': 'yahoo.com', 'yahooo.com': 'yahoo.com', 'yahoo.co': 'yahoo.com',
  'outlok.com': 'outlook.com', 'outllook.com': 'outlook.com', 'outlook.co': 'outlook.com',
  'iclould.com': 'icloud.com', 'icloud.co': 'icloud.com', 'iclound.com': 'icloud.com',
  'protonmai.com': 'protonmail.com', 'protomail.com': 'protonmail.com',
};

/**
 * DKIM selectors worth probing.
 *
 * A DKIM record is published at `<selector>._domainkey.<domain>`, and the
 * selector name is chosen by whoever sends the mail — so the selectors that
 * resolve are a direct list of the sending platforms an organisation uses,
 * including ones with no other DNS footprint. There is no way to enumerate
 * them; you check the conventional names each platform uses.
 */
export const DKIM_SELECTORS = [
  { selector: 'google', platform: 'Google Workspace' },
  { selector: 'selector1', platform: 'Microsoft 365' },
  { selector: 'selector2', platform: 'Microsoft 365' },
  { selector: 'k1', platform: 'Mailchimp / Mandrill' },
  { selector: 'k2', platform: 'Mailchimp' },
  { selector: 's1', platform: 'SendGrid / generic' },
  { selector: 's2', platform: 'SendGrid / generic' },
  { selector: 'mandrill', platform: 'Mandrill' },
  { selector: 'zendesk1', platform: 'Zendesk' },
  { selector: 'zendesk2', platform: 'Zendesk' },
  { selector: 'hs1-', platform: 'HubSpot', prefixMatch: true },
  { selector: 'mail', platform: 'generic' },
  { selector: 'default', platform: 'generic' },
  { selector: 'dkim', platform: 'generic' },
  { selector: 'smtp', platform: 'generic' },
  { selector: 'protonmail', platform: 'Proton Mail' },
  { selector: 'fm1', platform: 'Fastmail' },
  { selector: 'fm2', platform: 'Fastmail' },
  { selector: 'zoho', platform: 'Zoho' },
  { selector: 'pm', platform: 'Postmark' },
  { selector: 'sig1', platform: 'iCloud Custom Domain' },
  { selector: 'amazonses', platform: 'Amazon SES' },
  { selector: 'mailjet', platform: 'Mailjet' },
  { selector: 'sm', platform: 'SparkPost' },
  { selector: 'scph0', platform: 'SparkPost', prefixMatch: true },
  { selector: 'klaviyo', platform: 'Klaviyo' },
  { selector: 'intercom', platform: 'Intercom' },
  { selector: 'freshdesk', platform: 'Freshdesk' },
];

/**
 * SRV records worth checking. Each one that resolves names a service the
 * organisation runs — the Autodiscover and SIP entries in particular map an
 * internal collaboration stack that nothing else in DNS exposes.
 */
export const SRV_SERVICES = [
  { name: '_autodiscover._tcp', label: 'Exchange Autodiscover' },
  { name: '_sip._tls', label: 'SIP over TLS' },
  { name: '_sipfederationtls._tcp', label: 'Skype/Teams federation' },
  { name: '_sips._tcp', label: 'Secure SIP' },
  { name: '_xmpp-client._tcp', label: 'XMPP client' },
  { name: '_xmpp-server._tcp', label: 'XMPP server' },
  { name: '_caldavs._tcp', label: 'CalDAV' },
  { name: '_carddavs._tcp', label: 'CardDAV' },
  { name: '_imaps._tcp', label: 'IMAPS' },
  { name: '_submission._tcp', label: 'Mail submission' },
  { name: '_ldap._tcp', label: 'LDAP directory' },
  { name: '_kerberos._tcp', label: 'Kerberos KDC' },
  { name: '_minecraft._tcp', label: 'Minecraft server' },
  { name: '_matrix._tcp', label: 'Matrix homeserver' },
];

/* ---------------------------------------------------------------------- DNS */

/** Nameserver hostname → DNS operator. */
const DNS_PROVIDERS = [
  ['cloudflare.com', 'Cloudflare'],
  ['ns.cloudflare', 'Cloudflare'],
  ['awsdns', 'Amazon Route 53'],
  ['azure-dns', 'Azure DNS'],
  ['googledomains.com', 'Google Domains'],
  ['google.com', 'Google Cloud DNS'],
  ['domaincontrol.com', 'GoDaddy'],
  ['registrar-servers.com', 'Namecheap'],
  ['dnsimple', 'DNSimple'],
  ['dnsmadeeasy', 'DNS Made Easy'],
  ['nsone.net', 'NS1'],
  ['ultradns', 'UltraDNS / Vercara'],
  ['akam.net', 'Akamai Edge DNS'],
  ['akamaiedge', 'Akamai'],
  ['dynect.net', 'Oracle Dyn'],
  ['name-services.com', 'Oracle Dyn'],
  ['digitalocean.com', 'DigitalOcean'],
  ['linode.com', 'Linode / Akamai'],
  ['vultr.com', 'Vultr'],
  ['hetzner', 'Hetzner'],
  ['ovh.net', 'OVH'],
  ['gandi.net', 'Gandi'],
  ['porkbun.com', 'Porkbun'],
  ['name.com', 'Name.com'],
  ['dreamhost.com', 'DreamHost'],
  ['bluehost.com', 'Bluehost'],
  ['hostgator.com', 'HostGator'],
  ['siteground', 'SiteGround'],
  ['wordpress.com', 'WordPress.com'],
  ['wixdns.net', 'Wix'],
  ['squarespacedns', 'Squarespace'],
  ['shopify.com', 'Shopify'],
  ['vercel-dns', 'Vercel'],
  ['netlify.com', 'Netlify'],
  ['fastly.net', 'Fastly'],
  ['he.net', 'Hurricane Electric'],
  ['yandex', 'Yandex'],
  ['alidns', 'Alibaba Cloud DNS'],
  ['dnspod', 'Tencent DNSPod'],
  ['1and1', 'IONOS'],
  ['ui-dns', 'IONOS'],
  ['dns.hostinger', 'Hostinger'],
  ['bunny.net', 'BunnyDNS'],
  ['constellix', 'Constellix'],
  ['easydns', 'easyDNS'],
  ['rackspace', 'Rackspace'],
];

export const dnsProvider = (...ns) => matchTable(DNS_PROVIDERS, ...ns);

/* ------------------------------------------------------------------ hosting */

/** ASN holder / organisation string → hosting or cloud operator. */
const HOSTING_OPERATORS = [
  ['amazon', 'Amazon Web Services'],
  ['aws', 'Amazon Web Services'],
  ['google', 'Google Cloud'],
  ['microsoft', 'Microsoft Azure'],
  ['azure', 'Microsoft Azure'],
  ['digitalocean', 'DigitalOcean'],
  ['linode', 'Linode / Akamai'],
  ['akamai', 'Akamai'],
  ['cloudflare', 'Cloudflare'],
  ['fastly', 'Fastly'],
  ['ovh', 'OVH'],
  ['hetzner', 'Hetzner'],
  ['vultr', 'Vultr'],
  ['choopa', 'Vultr'],
  ['oracle', 'Oracle Cloud'],
  ['contabo', 'Contabo'],
  ['leaseweb', 'Leaseweb'],
  ['scaleway', 'Scaleway'],
  ['online s.a.s', 'Scaleway'],
  ['alibaba', 'Alibaba Cloud'],
  ['tencent', 'Tencent Cloud'],
  ['huawei', 'Huawei Cloud'],
  ['ibm', 'IBM Cloud'],
  ['rackspace', 'Rackspace'],
  ['godaddy', 'GoDaddy'],
  ['namecheap', 'Namecheap'],
  ['hostinger', 'Hostinger'],
  ['unified layer', 'Bluehost / Newfold'],
  ['newfold', 'Newfold Digital'],
  ['automattic', 'Automattic / WordPress.com'],
  ['shopify', 'Shopify'],
  ['squarespace', 'Squarespace'],
  ['wix', 'Wix'],
  ['vercel', 'Vercel'],
  ['netlify', 'Netlify'],
  ['fly.io', 'Fly.io'],
  ['railway', 'Railway'],
  ['render', 'Render'],
  ['heroku', 'Heroku'],
  ['github', 'GitHub'],
  ['gitlab', 'GitLab'],
  ['bunny', 'bunny.net'],
  ['stackpath', 'StackPath'],
  ['cdn77', 'CDN77'],
  ['g-core', 'Gcore'],
  ['m247', 'M247'],
  ['datacamp limited', 'Datacamp / CDN77'],
  ['psychz', 'Psychz Networks'],
  ['quadranet', 'QuadraNet'],
  ['colocrossing', 'ColoCrossing'],
  ['hostwinds', 'Hostwinds'],
  ['ionos', 'IONOS'],
  ['1&1', 'IONOS'],
  ['strato', 'STRATO'],
  ['aruba', 'Aruba.it'],
  ['selectel', 'Selectel'],
  ['timeweb', 'Timeweb'],
  ['beget', 'Beget'],
  ['yandex', 'Yandex Cloud'],
];

export const hostingOperator = (...values) => matchTable(HOSTING_OPERATORS, ...values);

/**
 * PTR patterns that reveal the platform and, on the big clouds, the region.
 *
 * Reverse DNS on cloud infrastructure is machine-generated and encodes more
 * than the operator name: `ec2-…​.eu-west-2.compute.amazonaws.com` pins the AWS
 * region, which is generally more precise than anything a geolocation database
 * will tell you about that address.
 */
const PTR_PATTERNS = [
  { pattern: /\.([a-z0-9-]+)\.compute\.amazonaws\.com$/i, platform: 'Amazon EC2', region: 1 },
  { pattern: /\.compute-1\.amazonaws\.com$/i, platform: 'Amazon EC2', fixedRegion: 'us-east-1' },
  { pattern: /\.([a-z0-9-]+)\.elb\.amazonaws\.com$/i, platform: 'AWS Elastic Load Balancer', region: 1 },
  { pattern: /\.bc\.googleusercontent\.com$/i, platform: 'Google Cloud' },
  { pattern: /\.googleusercontent\.com$/i, platform: 'Google' },
  { pattern: /\.1e100\.net$/i, platform: 'Google' },
  { pattern: /\.cloudapp\.(net|azure\.com)$/i, platform: 'Microsoft Azure' },
  { pattern: /\.([a-z0-9]+)\.clients\.your-server\.de$/i, platform: 'Hetzner' },
  { pattern: /static\.[0-9.]+\.clients\.your-server\.de$/i, platform: 'Hetzner' },
  { pattern: /\.digitalocean\.com$/i, platform: 'DigitalOcean' },
  { pattern: /\.linodeusercontent\.com$/i, platform: 'Linode' },
  { pattern: /\.members\.linode\.com$/i, platform: 'Linode' },
  { pattern: /\.vultrusercontent\.com$/i, platform: 'Vultr' },
  { pattern: /\.contaboserver\.net$/i, platform: 'Contabo' },
  { pattern: /\.ovh\.net$/i, platform: 'OVH' },
  { pattern: /\.hosteurope\./i, platform: 'Host Europe' },
  { pattern: /\.amazonaws\.com$/i, platform: 'Amazon Web Services' },
  { pattern: /\.cloudflare\.com$/i, platform: 'Cloudflare' },
  { pattern: /\.akamaitechnologies\.com$/i, platform: 'Akamai' },
  { pattern: /\.fastly\.net$/i, platform: 'Fastly' },
  { pattern: /\.stackpathdns\.com$/i, platform: 'StackPath' },
  { pattern: /\.dynamic\./i, platform: null, kind: 'dynamic residential' },
  { pattern: /\b(dsl|dial|dhcp|pool|cable|broadband|res|ppp)[-.]/i, platform: null, kind: 'residential access' },
  { pattern: /\b(static)[-.]/i, platform: null, kind: 'static allocation' },
  { pattern: /\b(vpn|tor|exit|proxy)[-.]/i, platform: null, kind: 'anonymising service (by name)' },
  { pattern: /\b(mail|mx|smtp)[-.0-9]*\./i, platform: null, kind: 'mail server' },
  { pattern: /\b(ns[0-9]*|dns)[-.]/i, platform: null, kind: 'nameserver' },
];

/**
 * Read whatever the PTR record is willing to say.
 * @returns {{platform: string|null, region: string|null, kind: string|null}|null}
 */
export function readPtr(ptr) {
  if (!ptr) return null;
  const out = { platform: null, region: null, kind: null };

  for (const rule of PTR_PATTERNS) {
    const match = ptr.match(rule.pattern);
    if (!match) continue;
    if (rule.platform && !out.platform) {
      out.platform = rule.platform;
      out.region = rule.fixedRegion ?? (rule.region ? match[rule.region] : null);
    }
    if (rule.kind && !out.kind) out.kind = rule.kind;
  }

  return out.platform || out.kind ? out : null;
}

/* ------------------------------------------------------- subdomain takeover */

/**
 * Dangling-CNAME fingerprints.
 *
 * A subdomain whose CNAME points at a SaaS platform that no longer serves it is
 * claimable by anyone who registers that name on the platform — the classic
 * subdomain takeover. The CNAME alone is only a candidate; confirmation is the
 * platform's specific "no such site" body, so both are recorded here.
 */
export const TAKEOVER_SIGNATURES = [
  { cname: /\.s3[.-][a-z0-9-]*\.amazonaws\.com$/i, service: 'AWS S3', body: /NoSuchBucket/i },
  { cname: /\.cloudfront\.net$/i, service: 'AWS CloudFront', body: /ERROR: The request could not be satisfied/i },
  { cname: /\.github\.io$/i, service: 'GitHub Pages', body: /There isn't a GitHub Pages site here/i },
  { cname: /\.herokuapp\.com$/i, service: 'Heroku', body: /No such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { cname: /\.azurewebsites\.net$/i, service: 'Azure App Service', body: /404 Web Site not found/i },
  { cname: /\.cloudapp\.azure\.com$/i, service: 'Azure', body: /404 Web Site not found/i },
  { cname: /\.trafficmanager\.net$/i, service: 'Azure Traffic Manager', body: /404 Web Site not found/i },
  { cname: /\.netlify\.(app|com)$/i, service: 'Netlify', body: /Not Found - Request ID/i },
  { cname: /\.vercel\.app$/i, service: 'Vercel', body: /DEPLOYMENT_NOT_FOUND|The deployment could not be found/i },
  { cname: /\.pantheonsite\.io$/i, service: 'Pantheon', body: /The gods are wise/i },
  { cname: /\.wpengine\.com$/i, service: 'WP Engine', body: /The site you were looking for couldn't be found/i },
  { cname: /\.ghost\.io$/i, service: 'Ghost', body: /Domain error|The thing you were looking for is no longer here/i },
  { cname: /\.surge\.sh$/i, service: 'Surge.sh', body: /project not found/i },
  { cname: /\.bitbucket\.io$/i, service: 'Bitbucket', body: /Repository not found/i },
  { cname: /\.readthedocs\.io$/i, service: 'Read the Docs', body: /unknown to Read the Docs/i },
  { cname: /\.zendesk\.com$/i, service: 'Zendesk', body: /Help Center Closed|this help center no longer exists/i },
  { cname: /\.helpscoutdocs\.com$/i, service: 'Help Scout', body: /No settings were found for this company/i },
  { cname: /\.statuspage\.io$/i, service: 'Statuspage', body: /You are being redirected|Better Status Communication/i },
  { cname: /\.uservoice\.com$/i, service: 'UserVoice', body: /This UserVoice subdomain is currently available/i },
  { cname: /\.desk\.com$/i, service: 'Desk.com', body: /Sorry, We Couldn't Find That Page/i },
  { cname: /\.freshdesk\.com$/i, service: 'Freshdesk', body: /May be this is still fresh/i },
  { cname: /\.tumblr\.com$/i, service: 'Tumblr', body: /Whatever you were looking for doesn't currently exist/i },
  { cname: /\.myshopify\.com$/i, service: 'Shopify', body: /Sorry, this shop is currently unavailable/i },
  { cname: /\.bigcartel\.com$/i, service: 'Big Cartel', body: /<h1>Oops! We couldn&#8217;t find that page/i },
  { cname: /\.launchrock\.com$/i, service: 'LaunchRock', body: /It looks like you may have taken a wrong turn/i },
  { cname: /\.webflow\.io$/i, service: 'Webflow', body: /The page you are looking for doesn't exist or has been moved/i },
  { cname: /\.wishpond\.com$/i, service: 'Wishpond', body: /https:\/\/www\.wishpond\.com\/404/i },
  { cname: /\.aftership\.com$/i, service: 'AfterShip', body: /Oops.*The page you're looking for doesn't exist/i },
  { cname: /\.tilda\.ws$/i, service: 'Tilda', body: /Please renew your subscription/i },
  { cname: /\.smugmug\.com$/i, service: 'SmugMug', body: /^\s*$/ },
  { cname: /\.fastly\.net$/i, service: 'Fastly', body: /Fastly error: unknown domain/i },
  { cname: /\.pagewiz\.net$/i, service: 'Pagewiz', body: /404/i },
  { cname: /\.canny\.io$/i, service: 'Canny', body: /Company Not Found/i },
  { cname: /\.frontify\.com$/i, service: 'Frontify', body: /404 - Page not found/i },
  { cname: /\.hatenablog\.com$/i, service: 'Hatena Blog', body: /404 Blog is not found/i },
  { cname: /\.gitbook\.io$/i, service: 'GitBook', body: /If you need specifics, here's the error/i },
];

/* -------------------------------------------------------- web technologies */

/**
 * Technology fingerprints, read from response headers, cookies and page source.
 *
 * This is deliberately a small, high-precision set rather than an attempt to
 * clone Wappalyzer: every entry here is a pattern that is diagnostic on its own,
 * because a fingerprint that guesses wrong is worse than no fingerprint at all.
 */
export const TECH_SIGNATURES = [
  // CMS and site builders
  { name: 'WordPress', category: 'CMS', html: [/\/wp-content\//i, /\/wp-includes\//i, /<meta name="generator" content="WordPress/i] },
  { name: 'Drupal', category: 'CMS', html: [/\/sites\/(all|default)\/(themes|modules)\//i, /Drupal\.settings/i], headers: { 'x-generator': /Drupal/i } },
  { name: 'Joomla', category: 'CMS', html: [/\/media\/jui\//i, /<meta name="generator" content="Joomla/i] },
  { name: 'Ghost', category: 'CMS', html: [/content="Ghost \d/i, /\/ghost\/api\//i] },
  { name: 'Craft CMS', category: 'CMS', headers: { 'x-powered-by': /Craft CMS/i } },
  { name: 'TYPO3', category: 'CMS', html: [/<meta name="generator" content="TYPO3/i] },
  { name: 'Contentful', category: 'CMS', html: [/images\.ctfassets\.net/i] },
  { name: 'Sanity', category: 'CMS', html: [/cdn\.sanity\.io/i] },
  { name: 'Squarespace', category: 'Site builder', html: [/static1\.squarespace\.com/i, /Squarespace\.afterBodyLoad/i] },
  { name: 'Wix', category: 'Site builder', html: [/static\.wixstatic\.com/i, /wix-?bolt/i] },
  { name: 'Webflow', category: 'Site builder', html: [/<html[^>]+data-wf-(page|site)/i, /assets\.website-files\.com/i] },
  { name: 'Framer', category: 'Site builder', html: [/framerusercontent\.com/i] },
  { name: 'Carrd', category: 'Site builder', html: [/carrd\.co/i] },

  // Commerce
  { name: 'Shopify', category: 'Ecommerce', html: [/cdn\.shopify\.com/i, /Shopify\.theme/i], headers: { 'x-shopid': /\d+/ } },
  { name: 'WooCommerce', category: 'Ecommerce', html: [/\/plugins\/woocommerce\//i, /woocommerce-page/i] },
  { name: 'Magento', category: 'Ecommerce', html: [/\/static\/version\d+\/frontend\//i, /Magento_/i] },
  { name: 'BigCommerce', category: 'Ecommerce', html: [/cdn\d*\.bigcommerce\.com/i] },
  { name: 'Stripe', category: 'Payments', html: [/js\.stripe\.com/i] },
  { name: 'PayPal', category: 'Payments', html: [/paypalobjects\.com/i, /paypal\.com\/sdk/i] },
  { name: 'Square', category: 'Payments', html: [/squareup\.com/i, /web\.squarecdn\.com/i] },

  // Frameworks
  { name: 'Next.js', category: 'Framework', html: [/\/_next\/static\//i, /__NEXT_DATA__/], headers: { 'x-powered-by': /Next\.js/i } },
  { name: 'Nuxt', category: 'Framework', html: [/__NUXT__/, /\/_nuxt\//i] },
  { name: 'React', category: 'Framework', html: [/data-reactroot/i, /react(-dom)?(\.production)?(\.min)?\.js/i] },
  { name: 'Vue.js', category: 'Framework', html: [/data-v-[0-9a-f]{8}/i, /vue(\.runtime)?(\.min)?\.js/i] },
  { name: 'Angular', category: 'Framework', html: [/ng-version="/i, /<app-root/i] },
  { name: 'Svelte / SvelteKit', category: 'Framework', html: [/svelte-[0-9a-z]{6}/i, /\/_app\/immutable\//i] },
  { name: 'Astro', category: 'Framework', html: [/astro-island/i, /<meta name="generator" content="Astro/i] },
  { name: 'Gatsby', category: 'Framework', html: [/___gatsby/i] },
  { name: 'Remix', category: 'Framework', html: [/__remixContext/] },
  { name: 'HTMX', category: 'Framework', html: [/htmx\.org|hx-(get|post|target)=/i] },
  { name: 'jQuery', category: 'Library', html: [/jquery[.-][\d.]+(\.min)?\.js/i] },
  { name: 'Bootstrap', category: 'Library', html: [/bootstrap(\.bundle)?(\.min)?\.(js|css)/i] },
  { name: 'Tailwind CSS', category: 'Library', html: [/tailwind(css)?(\.min)?\.css/i, /class="[^"]*\b(flex|grid) [a-z-]*(gap|space)-[xy]-\d/i] },

  // Backends
  { name: 'Laravel', category: 'Backend', cookies: [/laravel_session/i], headers: { 'set-cookie': /XSRF-TOKEN/i } },
  { name: 'Django', category: 'Backend', cookies: [/csrftoken|django/i] },
  { name: 'Ruby on Rails', category: 'Backend', cookies: [/_session_id|_rails/i], headers: { 'x-powered-by': /Phusion Passenger/i } },
  { name: 'ASP.NET', category: 'Backend', headers: { 'x-aspnet-version': /./, 'x-powered-by': /ASP\.NET/i }, cookies: [/ASP\.NET_SessionId/i] },
  { name: 'PHP', category: 'Backend', headers: { 'x-powered-by': /PHP\/[\d.]+/i }, cookies: [/PHPSESSID/i] },
  { name: 'Express', category: 'Backend', headers: { 'x-powered-by': /Express/i } },
  { name: 'Flask / Werkzeug', category: 'Backend', headers: { server: /Werkzeug/i } },
  { name: 'Spring Boot', category: 'Backend', cookies: [/JSESSIONID/i] },

  // Servers and edge
  { name: 'nginx', category: 'Web server', headers: { server: /nginx/i } },
  { name: 'Apache', category: 'Web server', headers: { server: /apache/i } },
  { name: 'LiteSpeed', category: 'Web server', headers: { server: /litespeed/i } },
  { name: 'Caddy', category: 'Web server', headers: { server: /caddy/i } },
  { name: 'Microsoft IIS', category: 'Web server', headers: { server: /Microsoft-IIS/i } },
  { name: 'OpenResty', category: 'Web server', headers: { server: /openresty/i } },
  { name: 'Envoy', category: 'Web server', headers: { server: /envoy/i } },
  { name: 'Cloudflare', category: 'CDN', headers: { 'cf-ray': /./, server: /cloudflare/i } },
  { name: 'Amazon CloudFront', category: 'CDN', headers: { 'x-amz-cf-id': /./ } },
  { name: 'Fastly', category: 'CDN', headers: { 'x-fastly-request-id': /./, 'x-served-by': /cache-/i } },
  { name: 'Akamai', category: 'CDN', headers: { 'x-akamai-transformed': /./, server: /AkamaiGHost/i } },
  { name: 'Vercel', category: 'Hosting', headers: { 'x-vercel-id': /./ } },
  { name: 'Netlify', category: 'Hosting', headers: { 'x-nf-request-id': /./, server: /Netlify/i } },
  { name: 'GitHub Pages', category: 'Hosting', headers: { 'x-github-request-id': /./ } },
  { name: 'Cloudflare Pages', category: 'Hosting', headers: { 'cf-pages': /./ } },
  { name: 'Google Frontend', category: 'Hosting', headers: { server: /Google Frontend|gws/i } },
  { name: 'AWS S3', category: 'Hosting', headers: { server: /AmazonS3/i, 'x-amz-request-id': /./ } },
  { name: 'Varnish', category: 'Cache', headers: { 'x-varnish': /./, via: /varnish/i } },

  // Security
  { name: 'Sucuri WAF', category: 'WAF', headers: { 'x-sucuri-id': /./ } },
  { name: 'Imperva / Incapsula', category: 'WAF', headers: { 'x-iinfo': /./, 'x-cdn': /Incapsula/i } },
  { name: 'Wordfence', category: 'WAF', cookies: [/wfvt_|wordfence/i] },
  { name: 'reCAPTCHA', category: 'Anti-bot', html: [/google\.com\/recaptcha/i] },
  { name: 'hCaptcha', category: 'Anti-bot', html: [/hcaptcha\.com/i] },
  { name: 'Cloudflare Turnstile', category: 'Anti-bot', html: [/challenges\.cloudflare\.com\/turnstile/i] },

  // Analytics, marketing and support — the richest ownership pivots
  { name: 'Google Analytics', category: 'Analytics', html: [/google-analytics\.com|googletagmanager\.com\/gtag/i] },
  { name: 'Google Tag Manager', category: 'Analytics', html: [/googletagmanager\.com\/gtm/i] },
  { name: 'Meta Pixel', category: 'Analytics', html: [/connect\.facebook\.net\/[a-z_]+\/fbevents\.js/i] },
  { name: 'Plausible', category: 'Analytics', html: [/plausible\.io\/js/i] },
  { name: 'Fathom', category: 'Analytics', html: [/cdn\.usefathom\.com/i] },
  { name: 'Matomo', category: 'Analytics', html: [/matomo\.(js|php)|piwik\.(js|php)/i] },
  { name: 'Hotjar', category: 'Analytics', html: [/static\.hotjar\.com/i] },
  { name: 'Mixpanel', category: 'Analytics', html: [/cdn\.mxpnl\.com/i] },
  { name: 'Segment', category: 'Analytics', html: [/cdn\.segment\.(com|io)/i] },
  { name: 'Amplitude', category: 'Analytics', html: [/cdn\.amplitude\.com/i] },
  { name: 'PostHog', category: 'Analytics', html: [/posthog\.com\/static|posthog\.init/i] },
  { name: 'Cloudflare Web Analytics', category: 'Analytics', html: [/static\.cloudflareinsights\.com/i] },
  { name: 'HubSpot', category: 'Marketing', html: [/js\.hs-scripts\.com|hs-analytics\.net/i] },
  { name: 'Marketo', category: 'Marketing', html: [/munchkin\.marketo\.net/i] },
  { name: 'Mailchimp', category: 'Marketing', html: [/chimpstatic\.com|list-manage\.com/i] },
  { name: 'Klaviyo', category: 'Marketing', html: [/static\.klaviyo\.com/i] },
  { name: 'Intercom', category: 'Support', html: [/widget\.intercom\.io|intercomcdn\.com/i] },
  { name: 'Zendesk', category: 'Support', html: [/static\.zdassets\.com|zendesk\.com\/embeddable/i] },
  { name: 'Drift', category: 'Support', html: [/js\.driftt\.com/i] },
  { name: 'Crisp', category: 'Support', html: [/client\.crisp\.chat/i] },
  { name: 'Tawk.to', category: 'Support', html: [/embed\.tawk\.to/i] },
  { name: 'Sentry', category: 'Monitoring', html: [/browser\.sentry-cdn\.com|@sentry\//i] },
  { name: 'New Relic', category: 'Monitoring', html: [/js-agent\.newrelic\.com|NREUM/] },
  { name: 'Datadog RUM', category: 'Monitoring', html: [/datadoghq-browser-agent/i] },
  { name: 'Cloudflare Turnstile', category: 'Anti-bot', html: [/turnstile/i] },

  // Identity
  { name: 'Auth0', category: 'Identity', html: [/auth0\.com\/js|cdn\.auth0\.com/i] },
  { name: 'Okta', category: 'Identity', html: [/okta\.com|oktacdn\.com/i] },
  { name: 'Clerk', category: 'Identity', html: [/clerk\.(accounts\.dev|com)/i] },
  { name: 'Firebase', category: 'Identity', html: [/firebaseapp\.com|firebase\.googleapis\.com/i] },
  { name: 'Supabase', category: 'Backend', html: [/supabase\.(co|io)/i] },
];

/**
 * Run the fingerprint table against one page's evidence.
 *
 * @param {{headers: Headers, html: string, cookies: string}} evidence
 * @returns {{name: string, category: string, evidence: string}[]}
 */
export function fingerprint({ headers, html = '', cookies = '' }) {
  const found = new Map();

  for (const signature of TECH_SIGNATURES) {
    let evidence = null;

    for (const [name, pattern] of Object.entries(signature.headers ?? {})) {
      const value = headers?.get?.(name);
      if (value && pattern.test(value)) {
        evidence = `${name}: ${value.slice(0, 80)}`;
        break;
      }
    }

    if (!evidence && signature.cookies) {
      const hit = signature.cookies.find((pattern) => pattern.test(cookies));
      if (hit) evidence = 'cookie name';
    }

    if (!evidence && signature.html && html) {
      const hit = signature.html.find((pattern) => pattern.test(html));
      if (hit) evidence = 'page source';
    }

    // First evidence wins; a technology detected twice is still one technology.
    if (evidence && !found.has(signature.name)) {
      found.set(signature.name, { name: signature.name, category: signature.category, evidence });
    }
  }

  return [...found.values()];
}

/* ------------------------------------------------------------------- DNSBL */

/**
 * DNS blocklists, queried the way a mail server queries them: an A lookup of
 * the reversed address under the zone, where an answer means "listed".
 *
 * Some operators — Spamhaus above all — refuse queries that arrive from a large
 * public resolver, and signal that refusal *as a listing* in the 127.255.255.x
 * range. Since all DNS here goes over public DoH, that case must be detected
 * and reported as "not usable from here" rather than as a hit; getting this
 * wrong would mark every address in the world as blocklisted.
 */
export const DNSBLS = [
  { zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN', codes: {
    '127.0.0.2': 'SBL — direct spam source',
    '127.0.0.3': 'CSS — snowshoe spam source',
    '127.0.0.4': 'XBL — exploited machine or open proxy',
    '127.0.0.9': 'DROP/EDROP — hijacked or leased to spammers',
    '127.0.0.10': 'PBL — end-user address, should not send mail directly',
    '127.0.0.11': 'PBL — end-user address, should not send mail directly',
  } },
  { zone: 'bl.spamcop.net', name: 'SpamCop', codes: { '127.0.0.2': 'Reported spam source' } },
  { zone: 'b.barracudacentral.org', name: 'Barracuda', codes: { '127.0.0.2': 'Reported spam source' } },
  { zone: 'dnsbl.sorbs.net', name: 'SORBS', codes: {
    '127.0.0.2': 'HTTP proxy', '127.0.0.3': 'SOCKS proxy', '127.0.0.4': 'Misc proxy',
    '127.0.0.5': 'SMTP relay', '127.0.0.6': 'Spam source', '127.0.0.7': 'Web form abuse',
    '127.0.0.9': 'Hijacked netblock', '127.0.0.10': 'Dynamic address range',
    '127.0.0.11': 'Bad DNS/no reverse', '127.0.0.12': 'Refuses non-relayed mail',
    '127.0.0.14': 'Compromised host',
  } },
  { zone: 'dnsbl-1.uceprotect.net', name: 'UCEPROTECT L1', codes: { '127.0.0.2': 'Sending host, single IP listing' } },
  { zone: 'spam.dnsbl.anonmails.de', name: 'Anonmails', codes: { '127.0.0.2': 'Spam source' } },
  { zone: 'all.s5h.net', name: 's5h', codes: { '127.0.0.2': 'Spam or proxy' } },
  { zone: 'bl.blocklist.de', name: 'blocklist.de', codes: { '127.0.0.2': 'Attacked or attacking host' } },
];

/** True when a DNSBL answer means "your resolver is blocked", not "listed". */
export const isResolverRefusal = (answer) =>
  /^127\.255\.255\./.test(answer) || answer === '127.0.0.1';

/* ------------------------------------------------- conventional public files */

/**
 * Files a site publishes on purpose, at conventional paths.
 *
 * Every one of these is a documented public-metadata convention — nothing here
 * is a probe for something the operator meant to hide. `ads.txt` in particular
 * is an unusually good ownership pivot: it lists the ad-network publisher
 * accounts a site sells through, and the same publisher ID across sites is a
 * direct link between them.
 */
export const WELL_KNOWN_FILES = [
  { path: '/robots.txt', label: 'robots.txt', kind: 'crawler policy' },
  { path: '/ads.txt', label: 'ads.txt', kind: 'ad seller declarations (IAB)' },
  { path: '/app-ads.txt', label: 'app-ads.txt', kind: 'mobile ad seller declarations' },
  { path: '/humans.txt', label: 'humans.txt', kind: 'credits, often names staff' },
  { path: '/.well-known/dnt-policy.txt', label: 'DNT policy', kind: 'tracking policy' },
  { path: '/.well-known/change-password', label: 'change-password', kind: 'credential-manager hint' },
];
