import pytest

from backend.src.decision_engine import classify_risk, recommend


@pytest.mark.parametrize(
    ("probability", "expected"),
    [
        (0.0, "LOW"),
        (0.3999, "LOW"),
        (0.40, "SUSPICIOUS"),
        (0.70, "SUSPICIOUS"),
        (0.7001, "HIGH"),
        (1.0, "HIGH"),
    ],
)
def test_risk_thresholds(probability, expected):
    assert classify_risk(probability)["level"] == expected


def test_risk_thresholds_can_be_configured():
    assert classify_risk(0.3, low_threshold=0.2, high_threshold=0.6)["level"] == "SUSPICIOUS"
    assert classify_risk(0.6, low_threshold=0.2, high_threshold=0.6)["level"] == "SUSPICIOUS"


def test_invalid_thresholds_are_rejected():
    with pytest.raises(ValueError):
        classify_risk(0.5, low_threshold=0.7, high_threshold=0.4)


def test_high_risk_recommendation_avoids_sensitive_data():
    message = recommend(0.9, [], {})
    assert "Avoid entering passwords, OTPs" in message
    assert "Based on the available signals" in message


def test_external_form_triggers_cautious_recommendation():
    message = recommend(0.2, [], {"external_form_count": 1})
    assert "form submits information to another domain" in message
    assert "Avoid entering sensitive information" in message


def test_unavailable_page_signals_are_not_reported_as_high_risk():
    message = recommend(
        0.2,
        [],
        {
            "dns_resolves": 1,
            "whois_available": 1,
            "domain_age_days": 365,
            "https_available": 1,
            "ssl_valid": 1,
            "webpage_reachable": 0,
        },
    )
    assert "overall model category is low risk" in message
    assert "page content could not be inspected" in message


def test_low_risk_is_not_described_as_proof_of_safety():
    message = recommend(
        0.2,
        [],
        {
            "dns_resolves": 1,
            "whois_available": 1,
            "domain_age_days": 365,
            "https_available": 1,
            "ssl_valid": 1,
            "webpage_reachable": 1,
        },
    )
    assert "not proof" in message
