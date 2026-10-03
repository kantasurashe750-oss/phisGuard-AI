"""Train and evaluate URL-only models with a domain-separated test set."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence, Tuple
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .feature_extractor import (
    EXTRACT_DOMAIN,
    LEXICAL_FEATURE_NAMES,
    extract_url_features,
    normalize_url,
)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
MODEL_PATH = os.path.join(ROOT, "backend", "models", "phishing_model.pkl")
MAX_TRAINING_ROWS = 50_000
LABEL_VALUES = {
    "0": 0,
    "0.0": 0,
    "good": 0,
    "legitimate": 0,
    "benign": 0,
    "safe": 0,
    "1": 1,
    "1.0": 1,
    "bad": 1,
    "phishing": 1,
    "malicious": 1,
}


def _load_dataset(dataset: str, max_rows: int) -> pd.DataFrame:
    source = pd.read_csv(dataset)
    source.columns = [str(column).strip().lower() for column in source.columns]
    if not {"url", "label"}.issubset(source.columns):
        raise ValueError("Dataset must contain `url` and `label` columns.")
    source = source.dropna(subset=["url", "label"]).copy()
    source["url"] = source["url"].astype(str).str.strip()
    raw_labels = source["label"].astype(str).str.strip().str.lower()
    labels = raw_labels.map(LABEL_VALUES)
    if labels.isna().any():
        unexpected = sorted(raw_labels[labels.isna()].unique().tolist())[:10]
        raise ValueError(
            "Labels must mean 0=legitimate or 1=phishing. "
            f"Unrecognized values: {unexpected}"
        )
    source["label"] = labels.astype(int)

    conflicting_urls = source.groupby("url")["label"].nunique()
    conflicting_urls = set(conflicting_urls[conflicting_urls > 1].index)
    if conflicting_urls:
        source = source[~source["url"].isin(conflicting_urls)].copy()
        print(f"Removed {len(conflicting_urls)} URLs with conflicting labels.")
    duplicate_count = int(source.duplicated(subset=["url"]).sum())
    source = source.drop_duplicates(subset=["url"]).reset_index(drop=True)
    unique_url_count = len(source)
    if duplicate_count:
        print(f"Removed {duplicate_count} duplicate URLs.")
    if source["label"].nunique() != 2:
        raise ValueError("Dataset must contain both legitimate and phishing examples.")

    if max_rows > 0 and len(source) > max_rows:
        sampled = []
        for _, group in source.groupby("label"):
            count = max(2, round(max_rows * len(group) / len(source)))
            sampled.append(group.sample(n=min(count, len(group)), random_state=42))
        source = (
            pd.concat(sampled)
            .sample(frac=1, random_state=42)
            .reset_index(drop=True)
        )
        print(
            f"Using a reproducible stratified sample of {len(source):,} "
            f"from {unique_url_count:,} unique URLs."
        )
    return source


def _domain_group(url: str) -> str:
    hostname = urlparse(url).hostname or ""
    extracted = EXTRACT_DOMAIN(hostname)
    return extracted.registered_domain or hostname.lower()


def _extract_dataset_features(
    source: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    rows = []
    valid_labels = []
    groups = []
    skipped = 0
    for index, row in enumerate(source.itertuples(index=False), start=1):
        try:
            normalized_url = normalize_url(str(row.url))
            rows.append(extract_url_features(normalized_url))
            valid_labels.append(int(row.label))
            groups.append(_domain_group(normalized_url))
        except ValueError as error:
            skipped += 1
            if skipped <= 5:
                print(f"Skipping dataset row {index}: {error}")
        if index % 5000 == 0 or index == len(source):
            print(f"Processed {index:,}/{len(source):,} URLs")

    if skipped:
        print(f"Skipped {skipped} invalid or unsupported URLs.")
    labels = pd.Series(valid_labels, dtype=int)
    if set(labels.unique()) != {0, 1} or labels.value_counts().min() < 2:
        raise ValueError(
            "After skipping invalid URLs, at least two examples of each label remain required."
        )
    features = pd.DataFrame(rows, columns=LEXICAL_FEATURE_NAMES)
    return features, labels, groups


def _domain_split(
    features: pd.DataFrame, labels: pd.Series, groups: Sequence[str]
) -> Tuple[np.ndarray, np.ndarray]:
    if len(set(groups)) < 5:
        raise ValueError(
            "At least five distinct registered domains are needed for domain-separated evaluation."
        )
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    overall_rate = float(labels.mean())
    candidates = []
    for train_indices, test_indices in splitter.split(features, labels, groups):
        if labels.iloc[train_indices].nunique() != 2 or labels.iloc[test_indices].nunique() != 2:
            continue
        test_rate = float(labels.iloc[test_indices].mean())
        score = abs(len(test_indices) / len(labels) - 0.2) + abs(
            test_rate - overall_rate
        )
        candidates.append((score, train_indices, test_indices))
    if not candidates:
        raise ValueError(
            "Could not create a domain-separated split containing both labels. "
            "Use more distinct legitimate and phishing domains."
        )
    _, train_indices, test_indices = min(candidates, key=lambda item: item[0])
    if set(groups[i] for i in train_indices) & set(groups[i] for i in test_indices):
        raise RuntimeError("Domain leakage detected between training and test sets.")
    return train_indices, test_indices


def evaluate(model: Any, x_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
    predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, 1]
    suspicious_or_higher = probabilities >= 0.40
    high_risk = probabilities > 0.70

    def threshold_metrics(predicted: np.ndarray) -> Dict[str, Any]:
        return {
            "precision": float(precision_score(y_test, predicted, zero_division=0)),
            "recall": float(recall_score(y_test, predicted, zero_division=0)),
            "confusion_matrix": confusion_matrix(y_test, predicted).tolist(),
        }

    return {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "brier_score": float(brier_score_loss(y_test, probabilities)),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "at_or_above_suspicious_0_40": threshold_metrics(suspicious_or_higher),
        "above_high_risk_0_70": threshold_metrics(high_risk),
    }


def train(
    dataset: str,
    selected: str,
    output: str = MODEL_PATH,
    max_rows: int = MAX_TRAINING_ROWS,
) -> Dict[str, Any]:
    source = _load_dataset(dataset, max_rows)
    features, labels, groups = _extract_dataset_features(source)
    train_indices, test_indices = _domain_split(features, labels, groups)
    x_train, x_test = features.iloc[train_indices], features.iloc[test_indices]
    y_train, y_test = labels.iloc[train_indices], labels.iloc[test_indices]
    train_domains = {groups[i] for i in train_indices}
    test_domains = {groups[i] for i in test_indices}

    candidates: Dict[str, Any] = {
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        ),
        "logistic_regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=2000, random_state=42),
        ),
    }
    try:
        from xgboost import XGBClassifier

        candidates["xgboost"] = XGBClassifier(
            n_estimators=250,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )
    except ImportError:
        print("XGBoost is unavailable; use --model random_forest or install xgboost.")
    if selected not in candidates:
        raise ValueError(f"Selected model {selected!r} is unavailable.")

    print(
        f"Domain-separated evaluation: {len(x_train):,} train rows, "
        f"{len(x_test):,} test rows; {len(train_domains):,} train domains, "
        f"{len(test_domains):,} unseen test domains."
    )
    print(
        "Label counts (0=legitimate, 1=phishing): "
        f"train={y_train.value_counts().sort_index().to_dict()}, "
        f"test={y_test.value_counts().sort_index().to_dict()}"
    )
    metrics = {}
    for name, model in candidates.items():
        model.fit(x_train, y_train)
        metrics[name] = evaluate(model, x_test, y_test)
        print(f"{name}: {json.dumps(metrics[name])}")

    chosen = candidates[selected]
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    artifact = {
        "trained": True,
        "model": chosen,
        "model_type": selected,
        "feature_names": LEXICAL_FEATURE_NAMES,
        "metrics": metrics[selected],
        "all_model_metrics": metrics,
        "evaluation": {
            "split": "stratified_group_5_fold_by_registered_domain",
            "train_rows": len(train_indices),
            "test_rows": len(test_indices),
            "train_domains": len(train_domains),
            "test_domains": len(test_domains),
            "train_label_counts": y_train.value_counts().sort_index().to_dict(),
            "test_label_counts": y_test.value_counts().sort_index().to_dict(),
        },
        "background": x_train.sample(min(100, len(x_train)), random_state=42),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(artifact, output)
    print(f"Saved trained model to {output}")
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data",
        required=True,
        help="CSV with url,label columns; good/bad labels and URL/Label headers are supported",
    )
    parser.add_argument(
        "--model",
        choices=["xgboost", "random_forest", "logistic_regression"],
        default="xgboost",
        help="Model to save after evaluating all available candidates",
    )
    parser.add_argument("--output", default=MODEL_PATH, help="Output joblib artifact path")
    parser.add_argument(
        "--max-rows",
        type=int,
        default=MAX_TRAINING_ROWS,
        help="Reproducible stratified sample size (0 uses the entire dataset)",
    )
    args = parser.parse_args()
    if args.max_rows < 0:
        parser.error("--max-rows must be zero or greater.")
    train(args.data, args.model, args.output, args.max_rows)


if __name__ == "__main__":
    main()
