"""Load a trained phishing model and explain individual predictions."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
import shap

from .feature_extractor import FEATURE_LABELS, FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "phishing_model.pkl")


class ModelNotTrainedError(RuntimeError):
    pass


class PhishingPredictor:
    def __init__(self, model_path: str = MODEL_PATH) -> None:
        self.model_path = model_path
        self.artifact: Optional[Dict[str, Any]] = None
        self.explainer: Optional[Any] = None

    @property
    def trained(self) -> bool:
        return self.artifact is not None

    def load(self) -> None:
        if not os.path.isfile(self.model_path):
            self.artifact = None
            self.explainer = None
            return
        artifact = joblib.load(self.model_path)
        if not isinstance(artifact, dict) or not artifact.get("trained"):
            raise ValueError("The model artifact is invalid or marked untrained.")
        if artifact.get("feature_names") != FEATURE_NAMES:
            raise ValueError("Model feature schema does not match the live feature extractor.")
        self.artifact = artifact
        if artifact["model_type"] == "logistic_regression":
            scaler = artifact["model"].named_steps["standardscaler"]
            classifier = artifact["model"].named_steps["logisticregression"]
            background = artifact["background"]
            self.explainer = shap.LinearExplainer(
                classifier, scaler.transform(background)
            )
        else:
            self.explainer = shap.TreeExplainer(artifact["model"])

    def predict(self, features: Dict[str, float]) -> Dict[str, Any]:
        if not self.trained or self.artifact is None or self.explainer is None:
            raise ModelNotTrainedError(
                "No trained model is available. Train one from a labeled URL dataset first."
            )
        row = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)
        model = self.artifact["model"]
        probability = float(model.predict_proba(row)[0][1])
        explanation_row = row
        if self.artifact["model_type"] == "logistic_regression":
            explanation_row = model.named_steps["standardscaler"].transform(row)
        shap_values = self.explainer.shap_values(explanation_row)
        if isinstance(shap_values, list):
            contributions = np.asarray(shap_values[1]).reshape(-1)
        else:
            values = np.asarray(shap_values)
            if values.ndim == 3:
                contributions = values[0, :, 1]
            else:
                contributions = values.reshape(-1)
        ranked = sorted(
            zip(FEATURE_NAMES, contributions.tolist()),
            key=lambda item: abs(item[1]),
            reverse=True,
        )[:3]
        display_values = {
            "ip_address": ("IP address used", "No IP address used"),
            "has_at_symbol": ("Present", "Not found"),
            "has_hyphen": ("Present", "Not found"),
            "is_shortened": ("Shortened URL", "Not a known shortener"),
            "has_punycode": ("Present", "Not found"),
            "https_token_in_url": ("Present", "Not found"),
            "whois_available": ("Available", "Unavailable"),
            "dns_resolves": ("Public DNS resolved", "Not resolved"),
            "ssl_valid": ("Valid", "Invalid or unavailable"),
            "https_available": ("HTTPS URL", "HTTP URL"),
            "webpage_reachable": ("Reached", "Not reached"),
        }
        explanation = [
            {
                "feature": name,
                "label": (
                    "Domain age unavailable"
                    if name == "domain_age_days"
                    and (features[name] < 0 or not features["whois_available"])
                    else FEATURE_LABELS[name]
                ),
                "value": float(features[name]),
                "display_value": (
                    "Unavailable"
                    if name == "domain_age_days"
                    and (features[name] < 0 or not features["whois_available"])
                    else f"{int(features[name])} days"
                    if name == "domain_age_days"
                    else (
                        "Valid certificate"
                        if features["ssl_valid"]
                        else "Invalid certificate"
                        if features["https_available"]
                        else "No HTTPS service"
                    )
                    if name == "ssl_valid"
                    else display_values[name][0 if features[name] else 1]
                    if name in display_values
                    else f"{int(features[name])} detected"
                    if name.endswith("_count") or name.endswith("_length")
                    else f"{features[name]:g}"
                ),
                "effect": "increases" if contribution >= 0 else "reduces",
                "risk_contribution": "phishing risk",
            }
            for name, contribution in ranked
        ]
        return {
            "probability": probability,
            "explanations": explanation,
            "model_type": self.artifact["model_type"],
        }
