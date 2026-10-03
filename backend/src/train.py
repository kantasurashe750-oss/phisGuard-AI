"""Train and evaluate models from a CSV containing `url` and `label` columns."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from requests import RequestException
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

from .feature_extractor import FEATURE_NAMES, extract_features

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
MODEL_PATH = os.path.join(ROOT, "backend", "models", "phishing_model.pkl")


def evaluate(model: Any, x_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
    predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, 1]
    return {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
    }


def train(dataset: str, selected: str, output: str = MODEL_PATH) -> Dict[str, Any]:
    source = pd.read_csv(dataset)
    if not {"url", "label"}.issubset(source.columns):
        raise ValueError("Dataset must contain `url` and `label` columns.")
    source = source.dropna(subset=["url", "label"])
    labels = pd.to_numeric(source["label"], errors="coerce")
    if labels.isna().any() or not set(labels.unique()).issubset({0, 1}):
        raise ValueError("Labels must use 0 for legitimate and 1 for phishing.")
    labels = labels.astype(int)
    if labels.value_counts().min() < 2:
        raise ValueError("At least two examples of each class are required for a stratified split.")
    if int(np.ceil(len(source) * 0.2)) < 2:
        raise ValueError("At least 10 labeled URLs are required for a stratified train/test split.")

    rows = []
    for index, url in enumerate(source["url"].astype(str), start=1):
        try:
            rows.append(extract_features(url))
        except (ValueError, RequestException) as error:
            raise ValueError(f"Could not extract features for dataset row {index}: {error}") from error
        if index % 25 == 0:
            print(f"Extracted features for {index}/{len(source)} URLs")
    x = pd.DataFrame(rows, columns=FEATURE_NAMES)
    x_train, x_test, y_train, y_test = train_test_split(
        x, labels, test_size=0.2, random_state=42, stratify=labels
    )
    candidates: Dict[str, Any] = {
        "random_forest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1
        ),
        "logistic_regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(class_weight="balanced", max_iter=2000, random_state=42),
        ),
    }
    try:
        from xgboost import XGBClassifier

        candidates["xgboost"] = XGBClassifier(
            n_estimators=300,
            max_depth=6,
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
        "feature_names": FEATURE_NAMES,
        "metrics": metrics[selected],
        "all_model_metrics": metrics,
        "background": x_train.sample(min(100, len(x_train)), random_state=42),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(artifact, output)
    print(f"Saved trained model to {output}")
    return artifact

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True, help="CSV with url,label columns (0=legitimate, 1=phishing)")
    parser.add_argument(
        "--model",
        choices=["xgboost", "random_forest", "logistic_regression"],
        default="xgboost",
        help="Model to save after evaluating all available candidates",
    )
    parser.add_argument("--output", default=MODEL_PATH, help="Output joblib artifact path")
    args = parser.parse_args()
    train(args.data, args.model, args.output)


if __name__ == "__main__":
    main()
