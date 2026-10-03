"""Shared URL and webpage feature extraction for training and live scans."""

from __future__ import annotations

import ipaddress
import http.client
import re
import socket
import ssl
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

REQUEST_TIMEOUT = (3.05, 5)
MAX_HTML_BYTES = 1_000_000
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "adf.ly", "bit.do", "lnkd.in", "shorturl.at",
}
SUSPICIOUS_KEYWORDS = {
    "account", "bonus", "confirm", "free", "gift", "login", "password",
    "secure", "signin", "update", "verify", "wallet",
}
SUSPICIOUS_JS = (
    "eval(", "atob(", "document.write(", "window.location", "location.href",
    "fromcharcode(",
)
EXTRACT_DOMAIN = tldextract.TLDExtract(suffix_list_urls=())

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "ip_address", "has_at_symbol", "has_hyphen", "dot_count",
    "subdomain_count", "is_shortened", "suspicious_keyword_count",
    "https_token_in_url", "special_char_count", "digit_count",
    "has_punycode", "domain_age_days", "whois_available", "dns_resolves",
    "ssl_valid", "https_available", "webpage_reachable", "iframe_count",
    "form_count", "external_form_count", "external_resource_count",
    "anchor_count", "external_anchor_count", "external_script_count",
    "suspicious_js_count", "password_field_count",
]

FEATURE_LABELS = {
    "url_length": "Unusually long URL",
    "hostname_length": "Long domain name",
    "path_length": "Long URL path",
    "query_length": "Long URL query",
    "ip_address": "Website uses an IP address instead of a domain",
    "has_at_symbol": "URL contains an @ symbol",
    "has_hyphen": "Domain contains a hyphen",
    "dot_count": "Many dots in the URL",
    "subdomain_count": "Several subdomains",
    "is_shortened": "URL uses a link-shortening service",
    "suspicious_keyword_count": "URL contains account or verification keywords",
    "https_token_in_url": "URL contains an HTTPS token outside its scheme",
    "special_char_count": "Many unusual URL characters",
    "digit_count": "Many digits in the URL",
    "has_punycode": "Domain uses encoded international characters",
    "domain_age_days": "Domain registration age",
    "whois_available": "Domain registration information is available",
    "dns_resolves": "Domain DNS lookup",
    "ssl_valid": "TLS certificate validity",
    "https_available": "HTTPS connection availability",
    "webpage_reachable": "Website response availability",
    "iframe_count": "Embedded frames on the page",
    "form_count": "Forms on the page",
    "external_form_count": "Forms submit to another domain",
    "external_resource_count": "Resources loaded from other domains",
    "anchor_count": "Links on the page",
    "external_anchor_count": "Links to other domains",
    "external_script_count": "Scripts loaded from other domains",
    "suspicious_js_count": "Potentially suspicious JavaScript patterns",
    "password_field_count": "Password-entry fields on the page",
}


def normalize_url(value: str) -> str:
    """Require an explicit web scheme and a valid hostname."""
    url = value.strip()
    if not url:
        raise ValueError("Enter a website URL.")
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only valid http:// and https:// website URLs can be scanned.")
    hostname = parsed.hostname
    if _is_ip(hostname) and not ipaddress.ip_address(hostname.strip("[]")).is_global:
        raise ValueError("Private and local IP addresses cannot be scanned.")
    if not _is_ip(hostname):
        try:
            ascii_hostname = hostname.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError("The URL contains an invalid hostname.") from error
        labels = ascii_hostname.split(".")
        if (
            not ascii_hostname
            or len(ascii_hostname) > 253
            or any(
                not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                for label in labels
            )
        ):
            raise ValueError("The URL contains an invalid hostname.")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("The URL contains an invalid port.") from error
    if port is not None and port != (443 if parsed.scheme == "https" else 80):
        raise ValueError("Only standard HTTP and HTTPS ports can be scanned.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials cannot be scanned.")
    return url


def _public_addresses(hostname: str, port: int) -> list:
    try:
        records = socket.getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM
        )
    except OSError:
        return []
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    try:
        if not addresses or any(
            not ipaddress.ip_address(address).is_global for address in addresses
        ):
            return []
    except ValueError:
        return []
    return addresses


def _domain_parts(hostname: str) -> Tuple[str, int]:
    extracted = EXTRACT_DOMAIN(hostname)
    registered = extracted.registered_domain or hostname
    subdomain_count = len([part for part in extracted.subdomain.split(".") if part])
    return registered, subdomain_count


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _has_public_dns(hostname: str) -> bool:
    if _is_ip(hostname):
        return ipaddress.ip_address(hostname.strip("[]")).is_global
    if (
        hostname in {"localhost", "localhost.localdomain"}
        or hostname.endswith((".localhost", ".local", ".internal"))
        or "." not in hostname
    ):
        return False
    addresses = []
    try:
        for record_type in ("A", "AAAA"):
            response = requests.get(
                "https://dns.google/resolve",
                params={"name": hostname, "type": record_type},
                headers={"Accept": "application/dns-json"},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            addresses.extend(
                answer["data"]
                for answer in response.json().get("Answer", [])
                if answer.get("type") in (1, 28)
            )
        return bool(addresses) and all(
            ipaddress.ip_address(address).is_global for address in addresses
        )
    except (requests.RequestException, ValueError, KeyError):
        return False


def _check_tls(hostname: str, port: int) -> Tuple[bool, bool]:
    addresses = _public_addresses(hostname, port)
    if not addresses:
        return False, False
    verified_context = ssl.create_default_context()
    for address in addresses:
        try:
            with socket.create_connection((address, port), timeout=3) as connection:
                with verified_context.wrap_socket(
                    connection, server_hostname=hostname
                ):
                    return True, True
        except ssl.SSLCertVerificationError:
            try:
                with socket.create_connection((address, port), timeout=3) as connection:
                    with ssl._create_unverified_context().wrap_socket(
                        connection, server_hostname=hostname
                    ):
                        return True, False
            except (OSError, ssl.SSLError, ValueError):
                continue
        except (OSError, ssl.SSLError, ValueError):
            continue
    return False, False


def _domain_registration(domain: str) -> Tuple[int, int]:
    """Return (age in days, lookup available) using the public RDAP service."""
    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}", timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 404:
            return -1, 0
        response.raise_for_status()
        events = response.json().get("events", [])
        registration = next(
            (
                event.get("eventDate")
                for event in events
                if event.get("eventAction") == "registration"
            ),
            None,
        )
        if not registration:
            return -1, 1
        registered_at = datetime.fromisoformat(registration.replace("Z", "+00:00"))
        age = max(0, (datetime.now(registered_at.tzinfo) - registered_at).days)
        return age, 1
    except (requests.RequestException, ValueError, TypeError, KeyError):
        return -1, 0


def _safe_page(
    url: str, initially_public: bool
) -> Tuple[Optional[str], Optional[str], bool]:
    """Fetch a bounded page while pinning each connection to a public DNS result."""
    if not initially_public:
        return None, None, False
    current = url
    for _ in range(4):
        connection = None
        try:
            parsed = urlparse(normalize_url(current))
            hostname = (parsed.hostname or "").lower()
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if not hostname or not _has_public_dns(hostname):
                return None, None, False
            addresses = _public_addresses(hostname, port)
            if not addresses:
                return None, None, False

            response = None
            connection = None
            for address in addresses:
                try:
                    if parsed.scheme == "https":
                        connection = http.client.HTTPSConnection(
                            hostname,
                            port,
                            timeout=REQUEST_TIMEOUT[1],
                            context=ssl.create_default_context(),
                        )
                    else:
                        connection = http.client.HTTPConnection(
                            hostname, port, timeout=REQUEST_TIMEOUT[1]
                        )
                    connection.sock = _connect_to_public_ip(
                        address,
                        port,
                        hostname,
                        parsed.scheme == "https",
                        connection,
                    )
                    path = parsed.path or "/"
                    if parsed.query:
                        path += "?" + parsed.query
                    connection.request(
                        "GET",
                        path,
                        headers={
                            "User-Agent": "PhishGuardAI/1.0 (educational scanner)",
                            "Connection": "close",
                        },
                    )
                    response = connection.getresponse()
                    break
                except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
                    if connection is not None:
                        connection.close()
                    connection = None
            if response is None or connection is None:
                return None, None, False

            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                response.read(16_384)
                connection.close()
                if not location:
                    return None, None, False
                current = urljoin(current, location)
                continue

            content_type = response.getheader("Content-Type", "").lower()
            body = response.read(MAX_HTML_BYTES + 1)[:MAX_HTML_BYTES]
            connection.close()
            body_text = body.decode("utf-8", errors="replace")
            return (
                body_text,
                current,
                "html" in content_type or "<html" in body_text.lower(),
            )
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            if connection is not None:
                connection.close()
            return None, None, False
    return None, None, False


def _connect_to_public_ip(
    address: str,
    port: int,
    hostname: str,
    use_tls: bool,
    connection: Any,
) -> socket.socket:
    sock = socket.create_connection((address, port), timeout=connection.timeout)
    if use_tls:
        try:
            return connection._context.wrap_socket(sock, server_hostname=hostname)
        except (OSError, ssl.SSLError):
            sock.close()
            raise
    return sock


def extract_features(value: str) -> Dict[str, float]:
    """Extract the fixed feature vector used by both training and prediction."""
    url = normalize_url(value)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    registered_domain, subdomain_count = _domain_parts(hostname)
    path_query = f"{parsed.path}?{parsed.query}"

    public_host = _has_public_dns(hostname)
    age_days, whois_available = (
        _domain_registration(registered_domain) if public_host else (-1, 0)
    )
    dns_resolves = int(public_host)
    https_port = (parsed.port or 443) if parsed.scheme == "https" else 443
    https_available, ssl_valid = (
        _check_tls(hostname, https_port) if public_host else (False, False)
    )

    html, final_url, is_html = _safe_page(url, public_host)
    soup = BeautifulSoup(html or "", "html.parser") if html and is_html else None
    page_host = (urlparse(final_url).hostname or hostname).lower() if final_url else hostname

    forms = soup.find_all("form") if soup else []
    external_forms = 0
    for form in forms:
        action = form.get("action", "").strip()
        target = urlparse(urljoin(final_url or url, action)).hostname
        if target and target.lower() != page_host:
            external_forms += 1

    anchors = soup.find_all("a", href=True) if soup else []
    external_anchors = sum(
        1
        for anchor in anchors
        if (urlparse(urljoin(final_url or url, anchor["href"])).hostname or "").lower()
        not in {"", page_host}
    )
    resource_tags = soup.find_all(["img", "link", "source"]) if soup else []
    external_resources = sum(
        1
        for tag in resource_tags
        if (urlparse(urljoin(final_url or url, tag.get("src") or tag.get("href") or "")).hostname or "").lower()
        not in {"", page_host}
    )
    scripts = soup.find_all("script", src=True) if soup else []
    external_scripts = sum(
        1
        for script in scripts
        if (urlparse(urljoin(final_url or url, script["src"])).hostname or "").lower()
        not in {"", page_host}
    )
    js_text = " ".join(script.get_text(" ", strip=True) for script in soup.find_all("script")) if soup else ""
    keyword_count = sum(
        1 for keyword in SUSPICIOUS_KEYWORDS if keyword in url.lower()
    )

    return {
        "url_length": float(len(url)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(parsed.path)),
        "query_length": float(len(parsed.query)),
        "ip_address": float(_is_ip(hostname)),
        "has_at_symbol": float("@" in url),
        "has_hyphen": float("-" in hostname),
        "dot_count": float(hostname.count(".")),
        "subdomain_count": float(subdomain_count),
        "is_shortened": float(hostname in SHORTENERS),
        "suspicious_keyword_count": float(keyword_count),
        "https_token_in_url": float("https" in (parsed.netloc + parsed.path).lower()),
        "special_char_count": float(len(re.findall(r"[=_%&?]", url))),
        "digit_count": float(sum(character.isdigit() for character in url)),
        "has_punycode": float("xn--" in hostname),
        "domain_age_days": float(age_days),
        "whois_available": float(whois_available),
        "dns_resolves": float(dns_resolves),
        "ssl_valid": float(ssl_valid),
        "https_available": float(https_available),
        "webpage_reachable": float(html is not None),
        "iframe_count": float(len(soup.find_all("iframe")) if soup else 0),
        "form_count": float(len(forms)),
        "external_form_count": float(external_forms),
        "external_resource_count": float(external_resources),
        "anchor_count": float(len(anchors)),
        "external_anchor_count": float(external_anchors),
        "external_script_count": float(external_scripts),
        "suspicious_js_count": float(
            sum(js_text.lower().count(pattern) for pattern in SUSPICIOUS_JS)
        ),
        "password_field_count": float(
            len(soup.select('input[type="password"]')) if soup else 0
        ),
    }
