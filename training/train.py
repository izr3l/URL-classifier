from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.stats import randint, uniform
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    auc,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import RandomizedSearchCV, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from dataset import DatasetConfig, build_feature_matrix
from feature_extractor import FEATURE_ORDER

CONTINUOUS_FEATURES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "dot_count",
    "hyphen_count",
    "subdomain_depth",
    "tld_risk_score",
    "registered_domain_length",
    "url_entropy",
    "hostname_entropy",
    "consonant_ratio",
    "suspicious_keyword_count",
    "path_depth",
    "query_param_count",
]


def build_preprocessor() -> ColumnTransformer:
    binary_features = [feature for feature in FEATURE_ORDER if feature not in CONTINUOUS_FEATURES]
    return ColumnTransformer(
        transformers=[
            ("continuous", StandardScaler(), CONTINUOUS_FEATURES),
            ("binary", "passthrough", binary_features),
        ]
    )


def evaluate(y_true: np.ndarray, probs: np.ndarray, threshold: float) -> dict[str, float]:
    preds = (probs >= threshold).astype(int)
    precision = precision_score(y_true, preds, zero_division=0)
    recall = recall_score(y_true, preds, zero_division=0)
    f1 = f1_score(y_true, preds, zero_division=0)
    auc_roc = roc_auc_score(y_true, probs)
    false_negative_rate = float(((y_true == 1) & (preds == 0)).sum() / max((y_true == 1).sum(), 1))
    false_positive_rate = float(((y_true == 0) & (preds == 1)).sum() / max((y_true == 0).sum(), 1))
    return {
        "auc_roc": float(auc_roc),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "false_negative_rate": false_negative_rate,
        "false_positive_rate": false_positive_rate,
    }


def choose_threshold(y_true: np.ndarray, probs: np.ndarray) -> tuple[float, float]:
    precision, recall, thresholds = precision_recall_curve(y_true, probs)
    pr_auc = auc(recall, precision)

    valid = np.where(recall[:-1] >= 0.95)[0]
    if len(valid) == 0:
        return 0.5, float(pr_auc)

    best_idx = valid[np.argmax(precision[valid])]
    return float(thresholds[best_idx]), float(pr_auc)


def train_models(X_train: pd.DataFrame, y_train: np.ndarray, scale_pos_weight: float) -> dict[str, Pipeline]:
    preprocessor = build_preprocessor()

    logistic = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", LogisticRegression(max_iter=500, class_weight="balanced")),
        ]
    )

    random_forest = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "model",
                RandomForestClassifier(
                    n_estimators=400,
                    random_state=42,
                    class_weight="balanced",
                    n_jobs=-1,
                ),
            ),
        ]
    )

    xgb_base = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "model",
                XGBClassifier(
                    objective="binary:logistic",
                    eval_metric="logloss",
                    n_estimators=300,
                    learning_rate=0.05,
                    max_depth=5,
                    subsample=0.9,
                    colsample_bytree=0.9,
                    scale_pos_weight=scale_pos_weight,
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )

    xgb_search = RandomizedSearchCV(
        estimator=xgb_base,
        param_distributions={
            "model__n_estimators": randint(100, 501),
            "model__max_depth": randint(3, 8),
            "model__learning_rate": uniform(0.01, 0.09),
            "model__subsample": uniform(0.7, 0.2),
            "model__colsample_bytree": uniform(0.7, 0.2),
        },
        n_iter=20,
        cv=3,
        random_state=42,
        n_jobs=-1,
        verbose=1,
        scoring="f1",
    )

    logistic.fit(X_train, y_train)
    random_forest.fit(X_train, y_train)
    xgb_search.fit(X_train, y_train)

    return {
        "logistic_regression": logistic,
        "random_forest": random_forest,
        "xgboost": xgb_search.best_estimator_,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    data_dir = project_root / "data"
    artifacts_dir = project_root / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    config = DatasetConfig(
        phishing_csv=data_dir / "phishing_urls.csv",
        legitimate_csv=data_dir / "legitimate_urls.csv",
    )

    X, y = build_feature_matrix(config)

    X_temp, X_test, y_temp, y_test = train_test_split(
        X,
        y,
        test_size=0.15,
        stratify=y,
        random_state=42,
    )

    validation_size = 0.15 / 0.85
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp,
        y_temp,
        test_size=validation_size,
        stratify=y_temp,
        random_state=42,
    )

    n_phishing = int((y_train == 1).sum())
    n_legitimate = int((y_train == 0).sum())
    scale_pos_weight = n_legitimate / max(n_phishing, 1)

    models = train_models(X_train, y_train.to_numpy(), scale_pos_weight=scale_pos_weight)

    model_metrics: dict[str, dict[str, float]] = {}
    best_name = ""
    best_f1 = -1.0
    best_threshold = 0.5

    for name, model in models.items():
        val_probs = model.predict_proba(X_val)[:, 1]
        threshold, pr_auc = choose_threshold(y_val.to_numpy(), val_probs)
        metrics = evaluate(y_val.to_numpy(), val_probs, threshold)
        metrics["pr_auc"] = pr_auc
        metrics["threshold"] = threshold
        model_metrics[name] = metrics

        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            best_name = name
            best_threshold = threshold

    best_model = models[best_name]
    test_probs = best_model.predict_proba(X_test)[:, 1]
    test_metrics = evaluate(y_test.to_numpy(), test_probs, best_threshold)
    test_metrics["threshold"] = best_threshold

    output = {
        "selected_model": best_name,
        "validation": model_metrics,
        "test": test_metrics,
        "feature_order": FEATURE_ORDER,
    }

    with (artifacts_dir / "metrics.json").open("w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    with (artifacts_dir / "feature_order.json").open("w", encoding="utf-8") as f:
        json.dump(FEATURE_ORDER, f, indent=2)

    # Feature importance powers explainability in the extension popup.
    if best_name == "xgboost":
        xgb_model = best_model.named_steps["model"]
        importance = pd.Series(xgb_model.feature_importances_, index=FEATURE_ORDER).sort_values(ascending=False)
        importance.to_json(artifacts_dir / "feature_importance.json", indent=2)

    joblib.dump(best_model, artifacts_dir / "model.joblib")

    print(f"Selected model: {best_name}")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
