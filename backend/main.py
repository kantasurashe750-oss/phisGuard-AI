"""FastAPI application for PhishGuard AI."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.src.decision_engine import classify_risk, recommend
from backend.src.feature_extractor import extract_features, normalize_url
from backend.src.history_store import initialize_history_store, save_scan_summary
from backend.src.predict import ModelNotTrainedError, PhishingPredictor

LOW_THRESHOLD = float(os.getenv("PHISHGUARD_LOW_THRESHOLD", "0.40"))
HIGH_THRESHOLD = float(os.getenv("PHISHGUARD_HIGH_THRESHOLD", "0.70"))
if not 0 <= LOW_THRESHOLD < HIGH_THRESHOLD <= 1:
    raise ValueError("Risk thresholds must satisfy 0 <= low < high <= 1.")

app = FastAPI(
    title="PhishGuard AI API",
    description="Explainable phishing prediction and decision assistance for an educational project.",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv(
        "PHISHGUARD_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

predictor = PhishingPredictor()
predictor.load()


@app.on_event("startup")
def initialize_scan_history() -> None:
    initialize_history_store()


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    scan_result: Optional[Dict[str, Any]] = None


def _scan(url_value: str) -> Dict[str, Any]:
    try:
        url = normalize_url(url_value)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if not predictor.trained:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "model_not_trained",
                "message": (
                    "The model is a placeholder because no trained model artifact exists. "
                    "Follow the README training steps to enable predictions."
                ),
            },
        )
    try:
        features = extract_features(url)
        prediction = predictor.predict(features)
    except ModelNotTrainedError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    risk = classify_risk(
        prediction["probability"],
        low_threshold=LOW_THRESHOLD,
        high_threshold=HIGH_THRESHOLD,
    )
    scorecard = {}
    for group in ("URL Structure", "Domain", "SSL", "DNS", "HTML / Forms"):
        if group == "URL Structure":
            scorecard[group] = (
                "red"
                if features["ip_address"]
                or features["has_at_symbol"]
                or features["url_length"] > 75
                or features["subdomain_count"] >= 3
                or features["suspicious_keyword_count"] > 0
                or features["is_shortened"]
                or features["has_punycode"]
                or features["special_char_count"] > 3
                else "green"
            )
        elif group == "Domain":
            scorecard[group] = (
                "orange"
                if not features["whois_available"] or features["domain_age_days"] < 0
                else "red"
                if 0 <= features["domain_age_days"] < 30
                else "green"
            )
        elif group == "SSL":
            scorecard[group] = (
                "green"
                if features["https_available"] and features["ssl_valid"]
                else "red"
                if features["https_available"]
                else "orange"
            )
        elif group == "DNS":
            scorecard[group] = "green" if features["dns_resolves"] else "orange"
        else:
            scorecard[group] = (
                "red"
                if features["external_form_count"] or features["suspicious_js_count"]
                else "orange"
                if not features["webpage_reachable"]
                else "green"
            )
    result = {
        "url": url,
        "probability": prediction["probability"],
        "risk": risk,
        "explanations": prediction["explanations"],
        "recommendation": recommend(
            prediction["probability"],
            prediction["explanations"],
            features,
            low_threshold=LOW_THRESHOLD,
            high_threshold=HIGH_THRESHOLD,
        ),
        "features": features,
        "scorecard": scorecard,
        "model_type": prediction["model_type"],
        "disclaimer": (
            "Based on the available signals, the model predicts this risk level. "
            "This result is not proof that a website is safe or malicious."
        ),
    }
    save_scan_summary(
        url=url,
        risk_level=risk["level"],
        probability=prediction["probability"],
        model_type=prediction["model_type"],
        explanations=prediction["explanations"],
    )
    return result


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "model_status": "trained" if predictor.trained else "placeholder",
        "model_type": predictor.artifact["model_type"] if predictor.artifact else None,
    }


@app.post("/scan")
def scan(request: ScanRequest) -> Dict[str, Any]:
    return _scan(request.url)


@app.post("/chat")
def chat(request: ChatRequest) -> Dict[str, Any]:
    message = request.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Enter a message.")
    found_url = re.search(r"https?://[^\s<>()]+|(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>()]*)?", message)
    if found_url:
        result = _scan(found_url.group(0).rstrip(".,!?"))
        percent = round(result["probability"] * 100)
        return {
            "reply": (
                f"{result['risk']['label']} — {percent}% predicted phishing probability. "
                f"{result['recommendation']}"
            ),
            "scan_result": result,
        }

    result = request.scan_result
    lowered = message.lower()
    if result is None:
        return {
            "reply": "Paste a website URL to scan it. I can then explain the result and suggest what to do."
        }
    if any(term in lowered for term in ("why", "explain", "detect", "suspicious", "what did")):
        reasons = result.get("explanations", [])
        if not reasons:
            return {"reply": "There are no model explanations available for this result."}
        items = "; ".join(
            f"{item.get('label', item.get('feature'))} {item.get('effect', 'affects')} risk"
            for item in reasons
        )
        return {"reply": f"The model's three strongest contributing signals were: {items}."}
    if any(term in lowered for term in ("do", "should", "next", "action", "advice")):
        return {"reply": result.get("recommendation", "Verify the website independently before entering sensitive information.")}
    if any(term in lowered for term in ("safe", "risk", "result", "probability", "score")):
        probability = round(float(result.get("probability", 0)) * 100)
        label = result.get("risk", {}).get("label", "UNKNOWN")
        return {
            "reply": (
                f"Based on the available signals, the model predicts {label.lower()} "
                f"({probability}% phishing probability). This is not proof that the site is safe or malicious."
            )
        }
    return {
        "reply": (
            "I can explain the scan, describe what the model detected, or recommend what to do next. "
            "Try asking “Why?” or “What should I do?”"
        )
    }
