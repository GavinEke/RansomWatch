"""Bounded HTTP fetching for public listing pages and Tor onion services."""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit


USER_AGENT = "Ransomwatch-Research/1.0 (+public metadata index)"
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml")


class FetchError(RuntimeError):
    def __init__(self, code: str, *, cause_type: str | None = None, http_status: int | None = None):
        super().__init__(code)
        self.code = code
        self.cause_type = cause_type
        self.http_status = http_status


@dataclass
class FetchResult:
    url: str
    body: str
    content_type: str
    status_code: int | None = None


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
        raise FetchError("dns_error", cause_type=type(exc).__name__) from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise FetchError("blocked_private_target")
    return clean


def _set_response_socket_timeout(response, seconds: float) -> None:
    """Tighten the connected socket timeout as the overall deadline advances."""
    raw = getattr(response, "raw", None)
    candidates = [getattr(getattr(raw, "_connection", None), "sock", None)]
    try:
        candidates.append(raw._fp.fp.raw._sock)
    except AttributeError:
        pass
    timeout = max(0.05, float(seconds))
    for candidate in candidates:
        setter = getattr(candidate, "settimeout", None)
        if setter:
            try:
                setter(timeout)
                return
            except OSError:
                continue


def fetch_html(
    url: str,
    *,
    tor_proxy: str = "socks5h://127.0.0.1:9050",
    timeout: tuple[int, int] = (10, 25),
    total_timeout: float = 25.0,
    max_bytes: int = 2_000_000,
    max_redirects: int = 5,
) -> FetchResult:
    """Fetch one bounded HTML page within a wall-clock response deadline."""
    try:
        import requests
    except ImportError as exc:
        raise FetchError("missing_requests_dependency", cause_type=type(exc).__name__) from exc

    deadline = time.monotonic() + max(0.1, float(total_timeout))
    current = _validate_public_target(url)
    session = requests.Session()
    session.trust_env = False
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9"}

    try:
        for redirect_count in range(max_redirects + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FetchError("deadline_exceeded")
            parsed = urlsplit(current)
            connect_timeout = min(float(timeout[0]), max(0.1, remaining * 0.4))
            read_timeout = min(float(timeout[1]), max(0.1, remaining - connect_timeout))
            proxies = (
                {"http": tor_proxy, "https": tor_proxy}
                if (parsed.hostname or "").lower().endswith(".onion")
                else None
            )
            try:
                response = session.get(
                    current,
                    headers=headers,
                    timeout=(connect_timeout, read_timeout),
                    proxies=proxies,
                    allow_redirects=False,
                    stream=True,
                )
            except requests.RequestException as exc:
                if time.monotonic() >= deadline:
                    raise FetchError("deadline_exceeded", cause_type=type(exc).__name__) from exc
                raise FetchError("network_error", cause_type=type(exc).__name__) from exc

            if time.monotonic() >= deadline:
                response.close()
                raise FetchError("deadline_exceeded")

            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                response.close()
                if not location or redirect_count >= max_redirects:
                    raise FetchError("redirect_limit")
                current = _validate_public_target(urljoin(current, location))
                continue

            if response.status_code >= 400:
                code = f"http_{response.status_code}"
                status_code = response.status_code
                response.close()
                raise FetchError(code, http_status=status_code)

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
                _set_response_socket_timeout(response, deadline - time.monotonic())
                for chunk in response.iter_content(chunk_size=8_192):
                    if time.monotonic() >= deadline:
                        raise FetchError("deadline_exceeded")
                    _set_response_socket_timeout(response, deadline - time.monotonic())
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > max_bytes:
                        raise FetchError("response_too_large")
                    chunks.append(chunk)
            except requests.RequestException as exc:
                if time.monotonic() >= deadline:
                    raise FetchError("deadline_exceeded", cause_type=type(exc).__name__) from exc
                raise FetchError("network_error", cause_type=type(exc).__name__) from exc
            finally:
                response.close()

            if time.monotonic() >= deadline:
                raise FetchError("deadline_exceeded")
            body_bytes = b"".join(chunks)
            if not content_type and not body_bytes.lstrip().lower().startswith(
                (b"<!doctype html", b"<html", b"<?xml")
            ):
                raise FetchError("unsupported_content_type")
            encoding = response.encoding or "utf-8"
            return FetchResult(
                current,
                body_bytes.decode(encoding, errors="replace"),
                content_type or "text/html",
                response.status_code,
            )

        raise FetchError("redirect_limit")
    finally:
        session.close()
