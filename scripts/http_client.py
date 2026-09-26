"""Bounded HTTP fetching for public listing pages and Tor onion services."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit


USER_AGENT = "Ransomwatch-Research/1.0 (+public metadata index)"
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml")


class FetchError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class FetchResult:
    url: str
    body: str
    content_type: str


def normalize_url(url: str) -> str:
    value = (url or "").strip().strip("\"'<>.,;")
    if not value:
        raise FetchError("invalid_url")
    if value.lower().endswith(".onion") or ".onion/" in value.lower():
        if "://" not in value:
            value = "http://" + value
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as exc:
        raise FetchError("invalid_url") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise FetchError("unsupported_scheme")
    if not parsed.hostname or parsed.username or parsed.password:
        raise FetchError("invalid_url")
    clean = urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))
    return urldefrag(clean)[0]


def _validate_public_target(url: str) -> str:
    clean = normalize_url(url)
    parsed = urlsplit(clean)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if hostname.endswith(".onion"):
        return clean
    if hostname in {"localhost", "metadata.google.internal"} or hostname.endswith(
        (".localhost", ".local", ".internal", ".lan")
    ):
        raise FetchError("blocked_private_target")

    try:
        literal_ip = ipaddress.ip_address(hostname)
        if not literal_ip.is_global:
            raise FetchError("blocked_private_target")
        return clean
    except ValueError:
        pass

    if "." not in hostname:
        raise FetchError("blocked_private_target")
    try:
        addresses = {
            ipaddress.ip_address(info[4][0])
            for info in socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        }
    except (OSError, ValueError) as exc:
        raise FetchError("dns_error") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise FetchError("blocked_private_target")
    return clean


def fetch_html(
    url: str,
    *,
    tor_proxy: str = "socks5h://127.0.0.1:9050",
    timeout: tuple[int, int] = (10, 25),
    max_bytes: int = 2_000_000,
    max_redirects: int = 5,
) -> FetchResult:
    """Fetch a bounded HTML page, validating each redirect target."""
    try:
        import requests
    except ImportError as exc:
        raise FetchError("missing_requests_dependency") from exc

    current = _validate_public_target(url)
    session = requests.Session()
    session.trust_env = False
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9"}

    for redirect_count in range(max_redirects + 1):
        parsed = urlsplit(current)
        proxies = (
            {"http": tor_proxy, "https": tor_proxy}
            if (parsed.hostname or "").lower().endswith(".onion")
            else None
        )
        try:
            response = session.get(
                current,
                headers=headers,
                timeout=timeout,
                proxies=proxies,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as exc:
            raise FetchError("network_error") from exc

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location or redirect_count >= max_redirects:
                raise FetchError("redirect_limit")
            current = _validate_public_target(urljoin(current, location))
            continue

        if response.status_code >= 400:
            code = f"http_{response.status_code}"
            response.close()
            raise FetchError(code)

        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type and not any(content_type.startswith(item) for item in ALLOWED_CONTENT_TYPES):
            response.close()
            raise FetchError("unsupported_content_type")

        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > max_bytes:
                    response.close()
                    raise FetchError("response_too_large")
            except ValueError:
                pass

        chunks: list[bytes] = []
        size = 0
        try:
            for chunk in response.iter_content(chunk_size=32_768):
                if not chunk:
                    continue
                size += len(chunk)
                if size > max_bytes:
                    raise FetchError("response_too_large")
                chunks.append(chunk)
        except requests.RequestException as exc:
            raise FetchError("network_error") from exc
        finally:
            response.close()

        body_bytes = b"".join(chunks)
        if not content_type and not body_bytes.lstrip().lower().startswith(
            (b"<!doctype html", b"<html", b"<?xml")
        ):
            raise FetchError("unsupported_content_type")
        encoding = response.encoding or "utf-8"
        return FetchResult(current, body_bytes.decode(encoding, errors="replace"), content_type or "text/html")

    raise FetchError("redirect_limit")
