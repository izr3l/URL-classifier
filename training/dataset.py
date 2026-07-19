from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from feature_extractor import FEATURE_ORDER, extract_features


@dataclass
class DatasetConfig:
    phishing_csv: Path
    legitimate_csv: Path


def _registered_domain(url: str) -> str:
    from urllib.parse import urlparse

    hostname = (urlparse(url).hostname or "").lower()
    parts = [part for part in hostname.split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


def _load_urls(path: Path, label: int, submission_time_col: str | None = None) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "url" not in df.columns:
        raise ValueError(f"CSV is missing required 'url' column: {path}")

    urls = df["url"].astype(str).tolist()
    if label == 1:
        import random, string
        BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook", "chase", "bank"]
        synthetic_phishing = []
        for i in range(2500):
            brand = random.choice(BRANDS)
            # Brand in registered domain (brand impersonation / combosquatting)
            synthetic_phishing.append(f"http://{brand}portal-{i}.com/l/eyjzijoi{i}")
            synthetic_phishing.append(f"http://{brand}-security-{i}.com/login")
            # Brand in subdomain
            synthetic_phishing.append(f"http://{brand}.security-update-{i}.com/login")
            # High entropy path (Base64-like)
            gibberish = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(100, 200)))
            synthetic_phishing.append(f"http://login-update-{i}.com/{gibberish}")
            # Suspicious keywords
            synthetic_phishing.append(f"http://verify-account-{i}.com/auth/login?token={random.randint(1000, 9999)}")
        
        urls.extend(synthetic_phishing)
        
    if label == 0:
        # Extreme augmentation for legitimate URLs to completely destroy structural bias!
        np.random.seed(42)
        schemes = np.random.choice(["https://", "http://", ""], size=len(urls), p=[0.7, 0.2, 0.1])
        
        WORDS = ["about", "contact", "us", "login", "auth", "products", "category", "item", "search", "results", "docs", "api", "v1", "endpoints", "user", "profile", "settings", "dashboard", "home", "index", "html", "php", "css", "js", "assets", "images", "static", "public", "private", "admin", "wp-content", "themes", "main", "style", "components", "base", "message", "scroller", "ui", "guide", "tutorial", "blog", "post", "article", "news", "press", "media", "events", "calendar", "help", "support", "faq"]
        
        def make_path():
            import random
            depth = random.randint(0, 10)
            if depth == 0: return ""
            return "/" + "/".join("-".join(random.choices(WORDS, k=random.randint(1, 3))) for _ in range(depth))
            
        def make_query():
            import random, string
            if random.random() < 0.5: return ""
            params = random.randint(1, 5)
            q = []
            for _ in range(params):
                k = random.choice(WORDS)
                # Queries can have some random IDs but mostly words to keep entropy sane
                v = random.choice(WORDS) + "".join(random.choices(string.digits, k=random.randint(0, 5)))
                q.append(f"{k}={v}")
            return "?" + "&".join(q)
            
        appended_paths = [make_path() for _ in range(len(urls))]
        appended_queries = [make_query() for _ in range(len(urls))]
        
        def augment(u, s, p, q):
            # If the URL already has a scheme, we keep the original scheme but append the path and query.
            # However, if s (the new scheme) is empty, we just append p and q.
            # Actually, to make it perfectly randomized, we strip existing schemes and apply the random one.
            import re
            u_clean = re.sub(r"^[a-z]+://", "", u)
            return f"{s}{u_clean}{p}{q}"
            
        urls = [augment(u, s, p, q) for u, s, p, q in zip(urls, schemes, appended_paths, appended_queries)]

    out = pd.DataFrame({"url": urls, "label": label})
    if submission_time_col and submission_time_col in df.columns:
        out["submission_time"] = pd.to_datetime(df[submission_time_col], errors="coerce")
    else:
        out["submission_time"] = pd.NaT
    return out


def build_feature_matrix(config: DatasetConfig) -> tuple[pd.DataFrame, pd.Series]:
    phishing = _load_urls(config.phishing_csv, label=1, submission_time_col="submission_time")
    legitimate = _load_urls(config.legitimate_csv, label=0)

    data = pd.concat([phishing, legitimate], ignore_index=True)
    data["registered_domain"] = data["url"].map(_registered_domain)

    # Deduplicate on registered domain to reduce campaign repetition leakage.
    data = data.drop_duplicates(subset=["registered_domain", "label"], keep="first")
    data = data.sort_values("submission_time", na_position="last").reset_index(drop=True)

    feature_rows = [extract_features(url) for url in data["url"].tolist()]
    X = pd.DataFrame(feature_rows, columns=FEATURE_ORDER)
    X = X.fillna(0)

    y = data["label"].astype(int)
    return X, y
