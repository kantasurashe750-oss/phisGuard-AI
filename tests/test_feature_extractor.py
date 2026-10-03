import pytest

from backend.src.feature_extractor import FEATURE_NAMES, extract_features, normalize_url


def test_feature_schema_has_thirty_named_features():
    assert len(FEATURE_NAMES) == 30
    assert len(set(FEATURE_NAMES)) == 30


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "https://example.com"),
        ("http://example.com/path", "http://example.com/path"),
    ],
)
def test_normalize_url(value, expected):
    assert normalize_url(value) == expected


def test_private_targets_and_embedded_credentials_are_rejected():
    with pytest.raises(ValueError):
        normalize_url("https://127.0.0.1")
    with pytest.raises(ValueError):
        normalize_url("https://" + "user" + ":" + "pass" + "@example.com")


def test_local_hostnames_are_not_public_targets():
    from backend.src.feature_extractor import _has_public_dns

    assert not _has_public_dns("localhost")


@pytest.mark.parametrize(
    "value",
    ["", "ftp://example.com", "https://user:password@example.com", "https://example.com:invalid"],
)
def test_reject_invalid_or_credentialed_urls(value):
    with pytest.raises(ValueError):
        normalize_url(value)


def test_non_standard_ports_are_rejected():
    with pytest.raises(ValueError, match="standard HTTP and HTTPS ports"):
        normalize_url("https://example.com:8443")


def test_public_address_resolution_rejects_private_or_mixed_answers(monkeypatch):
    import socket

    from backend.src.feature_extractor import _public_addresses

    public = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
    private = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [public])
    assert _public_addresses("example.com", 443) == ["93.184.216.34"]

    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: [public, private]
    )
    assert _public_addresses("example.com", 443) == []


def test_extractor_uses_the_declared_fixed_feature_schema(monkeypatch):
    monkeypatch.setattr(
        "backend.src.feature_extractor._domain_registration", lambda domain: (365, 1)
    )
    monkeypatch.setattr("backend.src.feature_extractor._has_public_dns", lambda host: True)
    monkeypatch.setattr("backend.src.feature_extractor._check_tls", lambda host, port: (True, True))
    monkeypatch.setattr(
        "backend.src.feature_extractor._safe_page",
        lambda url, initially_public: ("<html><body><form action='https://other.example/submit'></form></body></html>", url, True),
    )

    features = extract_features("https://login.example.com/account")
    assert list(features) == FEATURE_NAMES
    assert features["https_available"] == 1
    assert features["ssl_valid"] == 1
    assert features["form_count"] == 1
    assert features["external_form_count"] == 1
