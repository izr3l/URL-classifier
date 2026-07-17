from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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

    out = pd.DataFrame({"url": df["url"].astype(str), "label": label})
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
