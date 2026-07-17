export interface ParsedUrl {
  raw: string;
  protocol: string;
  hostname: string;
  path: string;
  query: string;
  tld: string;
  registeredDomain: string;
  subdomain: string;
}

function normalizeHost(hostname: string): string {
  return hostname.replace(/^\[|\]$/g, '').toLowerCase();
}

function getRegisteredDomain(hostname: string): string {
  const labels = hostname.split('.').filter(Boolean);
  if (labels.length <= 2) {
    return hostname;
  }
  return labels.slice(-2).join('.');
}

export function isIpAddress(hostname: string): boolean {
  const host = normalizeHost(hostname);
  const ipv4 = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/;
  const ipv6 = /^([0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}$/i;
  return ipv4.test(host) || ipv6.test(host);
}

export function parseUrl(rawUrl: string): ParsedUrl {
  const parsed = new URL(rawUrl);
  const hostname = normalizeHost(parsed.hostname);
  const registeredDomain = getRegisteredDomain(hostname);
  const subdomain = hostname.endsWith(registeredDomain)
    ? hostname.slice(0, hostname.length - registeredDomain.length).replace(/\.$/, '')
    : '';
  const tldParts = hostname.split('.');
  const tld = tldParts.length > 1 ? tldParts[tldParts.length - 1] : '';

  return {
    raw: rawUrl,
    protocol: parsed.protocol.replace(':', '').toLowerCase(),
    hostname,
    path: parsed.pathname || '',
    query: parsed.search ? parsed.search.slice(1) : '',
    tld,
    registeredDomain,
    subdomain
  };
}
