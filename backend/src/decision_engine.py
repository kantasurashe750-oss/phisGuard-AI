"""Risk categories and cautious, feature-aware user recommendations."""

from typing import Any, Dict, List


def classify_risk(
    probability: float, low_threshold: float = 0.40, high_threshold: float = 0.70
) -> Dict[str, str]:
    if not 0 <= low_threshold < high_threshold <= 1:
        raise ValueError("Risk thresholds must satisfy 0 <= low < high <= 1.")
    if probability < low_threshold:
        return {"level": "LOW", "label": "LOW RISK", "color": "green"}
    if probability <= high_threshold:
        return {"level": "SUSPICIOUS", "label": "SUSPICIOUS", "color": "orange"}
    return {"level": "HIGH", "label": "HIGH RISK", "color": "red"}


def recommend(
    probability: float,
    explanations: List[Dict[str, Any]],
    features: Dict[str, float],
    low_threshold: float = 0.40,
    high_threshold: float = 0.70,
) -> str:
    level = classify_risk(probability, low_threshold, high_threshold)["level"]
    reasons = {item["feature"] for item in explanations}
    urgent_signals = (
        features.get("external_form_count", 0) > 0
        or features.get("ssl_valid", 0) == 0 and features.get("https_available", 0) == 1
        or not features.get("https_available", 0)
        or not features.get("dns_resolves", 0)
        or not features.get("whois_available", 0)
        or features.get("domain_age_days", -1) < 0
        or not features.get("webpage_reachable", 0)
        or "domain_age_days" in reasons
        and 0 <= features.get("domain_age_days", -1) < 30
    )
    if level == "HIGH":
        return (
            "Based on the available signals, the predicted phishing risk is high. "
            "Avoid entering passwords, OTPs, payment information, or other sensitive data. "
            "If you need this service, open its official website using an independently "
            "known address and verify the request through a trusted channel."
        )
    if urgent_signals:
        warnings = []
        if features.get("external_form_count", 0) > 0:
            warnings.append("a form submits information to another domain")
        if features.get("ssl_valid", 0) == 0 and features.get("https_available", 0) == 1:
            warnings.append("the HTTPS certificate could not be validated")
        if not features.get("https_available", 0):
            warnings.append("no reachable HTTPS service was detected")
        if not features.get("dns_resolves", 0):
            warnings.append("public DNS could not be verified")
        if not features.get("whois_available", 0) or features.get("domain_age_days", -1) < 0:
            warnings.append("domain registration details are unavailable")
        if not features.get("webpage_reachable", 0):
            warnings.append("the page content could not be inspected")
        if (
            "domain_age_days" in reasons
            and 0 <= features.get("domain_age_days", -1) < 30
        ):
            warnings.append("the domain appears to be newly registered")
        return (
            f"The overall model category is {classify_risk(probability, low_threshold, high_threshold)['label'].lower()}, "
            f"but this scan also found that {' and '.join(warnings)}. "
            "Avoid entering sensitive information until you independently verify the website."
        )
    if level == "SUSPICIOUS":
        return (
            "Several indicators are associated with elevated risk. Verify the website "
            "through an independently known official source before entering sensitive "
            "information; do not rely on links in unexpected messages."
        )
    return (
        "Based on the available signals, the model predicts a low phishing risk and no "
        "major suspicious indicators were identified. This is not proof that the site is "
        "safe; continue normal cybersecurity precautions."
    )
