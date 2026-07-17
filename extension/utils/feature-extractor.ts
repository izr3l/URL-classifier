import { getTldRiskScore } from './tld-list';
import { isIpAddress, parseUrl } from './url-parser';

const SUSPICIOUS_KEYWORDS = [
  'login',
  'secure',
  'verify',
  'account',
  'update',
  'confirm',
  'banking',
  'signin'
];

const BRAND_KEYWORDS = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix'];

const SUSPICIOUS_EXTENSIONS = ['.exe', '.zip', '.php', '.asp'];
const SPECIAL_CHARS = /[@\-_~%=?&]/g;
const LOOKALIKE_PATTERN = /[013]/;

export interface FeatureVector {
  url_length: number;
  hostname_length: number;
  path_length: number;
  query_length: number;
  digit_count: number;
  digit_ratio: number;
  special_char_count: number;
  dot_count: number;
  hyphen_count: number;
  at_symbol_present: number;
  double_slash_in_path: number;
  subdomain_depth: number;
  is_ip_address: number;
  tld_risk_score: number;
  registered_domain_length: number;
  url_entropy: number;
  hostname_entropy: number;
  consonant_ratio: number;
  suspicious_keyword_count: number;
  brand_in_subdomain: number;
  lookalike_char_detected: number;
  encoded_url_in_path: number;
  https_present: number;
  path_depth: number;
  file_extension_suspicious: number;
  query_param_count: number;
}

export const FEATURE_ORDER: Array<keyof FeatureVector> = [
  'url_length',
  'hostname_length',
  'path_length',
  'query_length',
  'digit_count',
  'digit_ratio',
  'special_char_count',
  'dot_count',
  'hyphen_count',
  'at_symbol_present',
  'double_slash_in_path',
  'subdomain_depth',
  'is_ip_address',
  'tld_risk_score',
  'registered_domain_length',
  'url_entropy',
  'hostname_entropy',
  'consonant_ratio',
  'suspicious_keyword_count',
  'brand_in_subdomain',
  'lookalike_char_detected',
  'encoded_url_in_path',
  'https_present',
  'path_depth',
  'file_extension_suspicious',
  'query_param_count'
];

function shannonEntropy(value: string): number {
  if (!value) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const ch of value) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function consonantRatio(value: string): number {
  const letters = (value.toLowerCase().match(/[a-z]/g) ?? []).join('');
  if (!letters.length) {
    return 0;
  }
  const consonants = (letters.match(/[bcdfghjklmnpqrstvwxyz]/g) ?? []).length;
  return consonants / letters.length;
}

function countSuspiciousKeywords(path: string, query: string): number {
  const haystack = `${path.toLowerCase()} ${query.toLowerCase()}`;
  return SUSPICIOUS_KEYWORDS.reduce((sum, keyword) => {
    return sum + (haystack.includes(keyword) ? 1 : 0);
  }, 0);
}

function brandInSubdomain(subdomain: string, registeredDomain: string): number {
  const sub = subdomain.toLowerCase();
  const reg = registeredDomain.toLowerCase();
  const present = BRAND_KEYWORDS.some((brand) => sub.includes(brand) && !reg.includes(brand));
  return present ? 1 : 0;
}

function queryParamCount(query: string): number {
  if (!query) {
    return 0;
  }
  return Array.from(new URLSearchParams(query).keys()).length;
}

function pathDepth(path: string): number {
  return path
    .split('/')
    .filter((segment) => segment.length > 0)
    .length;
}

function hasSuspiciousFileExtension(path: string): number {
  const normalized = path.toLowerCase();
  return SUSPICIOUS_EXTENSIONS.some((ext) => normalized.endsWith(ext)) ? 1 : 0;
}

export function extractFeatureVector(url: string): FeatureVector {
  const parsed = parseUrl(url);
  const raw = parsed.raw;

  const digitCount = (raw.match(/\d/g) ?? []).length;
  const specialChars = raw.match(SPECIAL_CHARS) ?? [];
  const dotCount = (raw.match(/\./g) ?? []).length;
  const hyphenCount = (parsed.hostname.match(/-/g) ?? []).length;
  const query = parsed.query;
  const subDepth = parsed.subdomain ? parsed.subdomain.split('.').filter(Boolean).length : 0;

  const featureVector: FeatureVector = {
    url_length: raw.length,
    hostname_length: parsed.hostname.length,
    path_length: parsed.path.length,
    query_length: query.length,
    digit_count: digitCount,
    digit_ratio: raw.length > 0 ? digitCount / raw.length : 0,
    special_char_count: specialChars.length,
    dot_count: dotCount,
    hyphen_count: hyphenCount,
    at_symbol_present: raw.includes('@') ? 1 : 0,
    double_slash_in_path: raw.replace(/^[a-z]+:\/\//i, '').includes('//') ? 1 : 0,
    subdomain_depth: subDepth,
    is_ip_address: isIpAddress(parsed.hostname) ? 1 : 0,
    tld_risk_score: getTldRiskScore(parsed.tld),
    registered_domain_length: parsed.registeredDomain.split('.')[0]?.length ?? 0,
    url_entropy: shannonEntropy(raw),
    hostname_entropy: shannonEntropy(parsed.hostname),
    consonant_ratio: consonantRatio(parsed.hostname),
    suspicious_keyword_count: countSuspiciousKeywords(parsed.path, query),
    brand_in_subdomain: brandInSubdomain(parsed.subdomain, parsed.registeredDomain),
    lookalike_char_detected: LOOKALIKE_PATTERN.test(parsed.hostname + parsed.path) ? 1 : 0,
    encoded_url_in_path: /http%3a|url=http/i.test(`${parsed.path}?${query}`) ? 1 : 0,
    https_present: parsed.protocol === 'https' ? 1 : 0,
    path_depth: pathDepth(parsed.path),
    file_extension_suspicious: hasSuspiciousFileExtension(parsed.path),
    query_param_count: queryParamCount(query)
  };

  return featureVector;
}

export function extractFeatures(url: string): number[] {
  const vector = extractFeatureVector(url);
  return FEATURE_ORDER.map((key) => vector[key]);
}
