from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, asdict
from ipaddress import ip_address
from urllib.parse import parse_qsl, urlparse

SUSPICIOUS_KEYWORDS = [
    "login",
    "secure",
    "verify",
    "account",
    "update",
    "confirm",
    "banking",
    "signin",
]

BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix"]
SUSPICIOUS_EXTENSIONS = (".exe", ".zip", ".php", ".asp")
TLD_RISK_SCORES = {
    "tk": 1.0,
    "ml": 1.0,
    "ga": 0.95,
    "cf": 0.95,
    "gq": 0.9,
    "xyz": 0.75,
    "top": 0.7,
    "click": 0.65,
    "work": 0.6,
    "fit": 0.55,
    "rest": 0.55,
    "buzz": 0.5,
}

FEATURE_ORDER = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "dot_count",
    "hyphen_count",
    "at_symbol_present",
    "double_slash_in_path",
    "subdomain_depth",
    "is_ip_address",
    "tld_risk_score",
    "registered_domain_length",
    "url_entropy",
    "hostname_entropy",
    "consonant_ratio",
    "suspicious_keyword_count",
    "brand_in_subdomain",
    "lookalike_char_detected",
    "encoded_url_in_path",
    "https_present",
    "path_depth",
    "file_extension_suspicious",
    "query_param_count",
]


@dataclass
class FeatureVector:
    url_length: float
    hostname_length: float
    path_length: float
    query_length: float
    digit_count: float
    digit_ratio: float
    special_char_count: float
    dot_count: float
    hyphen_count: float
    at_symbol_present: float
    double_slash_in_path: float
    subdomain_depth: float
    is_ip_address: float
    tld_risk_score: float
    registered_domain_length: float
    url_entropy: float
    hostname_entropy: float
    consonant_ratio: float
    suspicious_keyword_count: float
    brand_in_subdomain: float
    lookalike_char_detected: float
    encoded_url_in_path: float
    https_present: float
    path_depth: float
    file_extension_suspicious: float
    query_param_count: float


def _registered_domain(hostname: str) -> str:
    parts = [part for part in hostname.lower().split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


def _is_ip_address(hostname: str) -> bool:
    host = hostname.strip("[]")
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _consonant_ratio(text: str) -> float:
    letters = re.findall(r"[a-z]", text.lower())
    if not letters:
        return 0.0
    consonants = len(re.findall(r"[bcdfghjklmnpqrstvwxyz]", "".join(letters)))
    return consonants / len(letters)


def _subdomain(hostname: str, registered_domain: str) -> str:
    if hostname.endswith(registered_domain):
        candidate = hostname[: -len(registered_domain)].rstrip(".")
        return candidate
    return ""


def _path_depth(path: str) -> int:
    return len([segment for segment in path.split("/") if segment])


def extract_feature_vector(url: str) -> FeatureVector:
    parsed = urlparse(url)
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    registered_domain = _registered_domain(hostname)
    subdomain = _subdomain(hostname, registered_domain)
    tld = hostname.split(".")[-1] if "." in hostname else ""

    digit_count = len(re.findall(r"\d", url))
    special_char_count = len(re.findall(r"[@\-_~%=?&]", url))
    query = parsed.query or ""
    path = parsed.path or ""

    has_brand_in_subdomain = any(
        brand in subdomain and brand not in registered_domain for brand in BRANDS
    )

    keyword_haystack = f"{path.lower()} {query.lower()}"
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in keyword_haystack)

    vector = FeatureVector(
        url_length=float(len(url)),
        hostname_length=float(len(hostname)),
        path_length=float(len(path)),
        query_length=float(len(query)),
        digit_count=float(digit_count),
        digit_ratio=float(digit_count / len(url) if url else 0.0),
        special_char_count=float(special_char_count),
        dot_count=float(url.count(".")),
        hyphen_count=float(hostname.count("-")),
        at_symbol_present=float("@" in url),
        double_slash_in_path=float("//" in re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE)),
        subdomain_depth=float(len([part for part in subdomain.split(".") if part])),
        is_ip_address=float(_is_ip_address(hostname)),
        tld_risk_score=float(TLD_RISK_SCORES.get(tld, 0.0)),
        registered_domain_length=float(len(registered_domain.split(".")[0]) if registered_domain else 0),
        url_entropy=float(_entropy(url)),
        hostname_entropy=float(_entropy(hostname)),
        consonant_ratio=float(_consonant_ratio(hostname)),
        suspicious_keyword_count=float(suspicious_keyword_count),
        brand_in_subdomain=float(has_brand_in_subdomain),
        lookalike_char_detected=float(bool(re.search(r"[013]", f"{hostname}{path}"))),
        encoded_url_in_path=float(bool(re.search(r"http%3a|url=http", f"{path}?{query}", re.IGNORECASE))),
        https_present=float((parsed.scheme or "").lower() == "https"),
        path_depth=float(_path_depth(path)),
        file_extension_suspicious=float(path.lower().endswith(SUSPICIOUS_EXTENSIONS)),
        query_param_count=float(len(parse_qsl(query, keep_blank_values=True))),
    )

    return vector


def extract_features(url: str) -> list[float]:
    vector = asdict(extract_feature_vector(url))
    return [float(vector[key]) for key in FEATURE_ORDER]
