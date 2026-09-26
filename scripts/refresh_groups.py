#!/usr/bin/env python3
"""Refresh group metadata and direct leak-site endpoints from WatchGuard."""

from __future__ import annotations

import argparse
import re
import sys
import time
import unicodedata
from collections import deque
from pathlib import Path
from urllib.parse import parse_qs, unquote, urljoin, urlparse

from html_dom import Element, parse_html
from http_client import FetchError, fetch_html, normalize_url
from json_io import read_json, utc_now, write_json_atomic


ROOT = Path(__file__).resolve().parents[1]
TRACKER_URL = "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker"
OUTPUT_PATH = ROOT / "site" / "data" / "groups.json"
MAX_TRACKER_PAGES = 100
PROFILE_DELAY_SECONDS = 0.4
WATCHGUARD_HOSTS = {"watchguard.com", "www.watchguard.com"}
MESSENGER_HOSTS = {
    "t.me", "telegram.me", "telegram.org", "discord.com", "discord.gg",
    "wa.me", "whatsapp.com", "signal.me", "session.foundation",
    "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com",
    "youtu.be", "reddit.com",
}
ONION_PATTERN = re.compile(r"\b([a-z2-7]{16,56}\.onion(?:/[^\s<>\"']*)?)", re.I)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.I)


def clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def slugify(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", normalized.lower()).strip("-")
    return slug or "unknown"


def _is_watchguard(hostname: str | None) -> bool:
    host = (hostname or "").lower().rstrip(".")
    return host in WATCHGUARD_HOSTS or host.endswith(".watchguard.com")


def _profile_group_id(url: str) -> str | None:
    parsed = urlparse(url)
    if not _is_watchguard(parsed.hostname):
        return None
    prefix = "/wgrd-security-hub/ransomware-tracker/"
    path = unquote(parsed.path)
    if not path.startswith(prefix):
        return None
    slug = path[len(prefix):].strip("/")
    if not slug or "/" in slug:
        return None
    return slugify(slug)


def _same_tracker_index(url: str) -> bool:
    parsed = urlparse(url)
    return (
        _is_watchguard(parsed.hostname)
        and parsed.path.rstrip("/") == "/wgrd-security-hub/ransomware-tracker"
    )


def _page_key(url: str) -> str:
    parsed = urlparse(url)
    values = parse_qs(parsed.query).get("page")
    return values[0] if values else "0"


def _row_for(anchor: Element) -> Element | None:
    return next((item for item in anchor.ancestors() if item.tag == "tr"), None)


def _cells(row: Element) -> list[Element]:
    direct = [child for child in row.children if isinstance(child, Element) and child.tag in {"td", "th"}]
    if direct:
        return direct
    return [item for item in row.iter() if item.tag in {"td", "th"}]


def _table_header_map(row: Element) -> dict[str, int]:
    table = next((item for item in row.ancestors() if item.tag == "table"), None)
    if table is None:
        return {}
    header_row = next(
        (item for item in table.iter("tr") if any(cell.tag == "th" for cell in _cells(item))),
        None,
    )
    if header_row is None:
        return {}
    return {
        clean_text(cell.text()).casefold(): index
        for index, cell in enumerate(_cells(header_row))
        if clean_text(cell.text())
    }


def _column(cells: list[Element], headers: dict[str, int], *terms: str) -> str | None:
    for heading, index in headers.items():
        if any(term in heading for term in terms) and index < len(cells):
            value = clean_text(cells[index].text())
            return value or None
    return None


def parse_tracker_page(markup: str, page_url: str) -> tuple[list[dict], list[str]]:
    """Return group rows and discovered tracker pagination URLs."""
    root = parse_html(markup)
    groups_by_id: dict[str, dict] = {}
    page_links: list[str] = []

    for anchor in root.iter("a"):
        href = anchor.attrs.get("href")
        if not href:
            continue
        absolute = urljoin(page_url, str(href))
        if _same_tracker_index(absolute) and "page" in parse_qs(urlparse(absolute).query):
            page_links.append(absolute)

        group_id = _profile_group_id(absolute)
        name = clean_text(anchor.text())
        if not group_id or not name:
            continue

        row = _row_for(anchor)
        cells = _cells(row) if row else []
        headers = _table_header_map(row) if row else {}
        row_text = clean_text(row.text()) if row else name
        first_cell = clean_text(cells[0].text()) if cells else ""
        status_text = (first_cell + " " + row_text).casefold()
        if re.search(r"\binactive\b", status_text):
            status = "inactive"
        elif re.search(r"\bactive\b", status_text):
            status = "active"
        else:
            status = "unknown"

        group = {
            "group_id": group_id,
            "name": name,
            "status": status,
            "types": _column(cells, headers, "type") or None,
            "first_seen": _column(cells, headers, "first seen"),
            "last_seen": _column(cells, headers, "last seen"),
            "profile_url": absolute,
        }
        existing = groups_by_id.get(group_id)
        if existing:
            for field in ("types", "first_seen", "last_seen"):
                if not existing.get(field) and group.get(field):
                    existing[field] = group[field]
            if existing["status"] == "unknown" and status != "unknown":
                existing["status"] = status
        else:
            groups_by_id[group_id] = group

    return list(groups_by_id.values()), list(dict.fromkeys(page_links))


def _host_is_messenger(hostname: str | None) -> bool:
    host = (hostname or "").lower().rstrip(".")
    return any(host == item or host.endswith("." + item) for item in MESSENGER_HOSTS)


def _site_record(url: str) -> dict | None:
    try:
        normalized = normalize_url(url)
    except FetchError:
        return None
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    if _is_watchguard(host) or _host_is_messenger(host):
        return None
    kind = "onion" if host.endswith(".onion") else "website"
    return {"kind": kind, "url": normalized}


def extract_leak_sites(markup: str, profile_url: str) -> list[dict]:
    """Extract direct web/Tor endpoints while excluding messaging services."""
    root = parse_html(markup)
    found: dict[str, dict] = {}

    for anchor in root.iter("a"):
        href = anchor.attrs.get("href")
        if not href:
            continue
        item = _site_record(urljoin(profile_url, str(href)))
        if item:
            found[item["url"].casefold()] = item

    visible_text = root.text()
    for match in ONION_PATTERN.finditer(visible_text):
        value = match.group(1).rstrip(".,;:)")
        item = _site_record(value)
        if item:
            found[item["url"].casefold()] = item
    for match in URL_PATTERN.finditer(visible_text):
        value = match.group(0).rstrip(".,;:)")
        item = _site_record(value)
        if item:
            found[item["url"].casefold()] = item

    return sorted(found.values(), key=lambda item: item["url"])


def collect_groups(
    tracker_url: str = TRACKER_URL,
    *,
    fetcher=fetch_html,
    sleep=time.sleep,
    previous: dict | None = None,
) -> dict:
    previous_groups = {
        str(group.get("group_id")): group
        for group in (previous or {}).get("groups", [])
        if isinstance(group, dict) and group.get("group_id")
    }
    queue = deque([tracker_url])
    visited_pages: set[str] = set()
    groups: dict[str, dict] = {}
    profiles: list[dict] = []

    while queue and len(visited_pages) < MAX_TRACKER_PAGES:
        page_url = queue.popleft()
        page_key = _page_key(page_url)
        if page_key in visited_pages:
            continue
        visited_pages.add(page_key)
        try:
            result = fetcher(page_url)
        except FetchError as exc:
            raise RuntimeError(f"WatchGuard tracker page {page_key} failed: {exc.code}") from exc
        page_groups, page_links = parse_tracker_page(result.body, result.url)
        for group in page_groups:
            existing = groups.get(group["group_id"])
            if existing is None:
                groups[group["group_id"]] = group
            else:
                for field in ("types", "first_seen", "last_seen"):
                    if not existing.get(field) and group.get(field):
                        existing[field] = group[field]
        for link in page_links:
            if _page_key(link) not in visited_pages:
                queue.append(link)
        if queue:
            sleep(PROFILE_DELAY_SECONDS)

    if queue:
        raise RuntimeError(f"WatchGuard pagination exceeded {MAX_TRACKER_PAGES} pages")
    if not groups:
        raise RuntimeError("No WatchGuard group profiles found; refusing to replace the catalog")

    for group in sorted(groups.values(), key=lambda item: item["name"].casefold()):
        prior = previous_groups.get(group["group_id"], {})
        try:
            result = fetcher(group["profile_url"])
            group["leak_sites"] = extract_leak_sites(result.body, result.url)
            group["profile_status"] = "ok"
            group["profile_checked_at"] = utc_now()
        except FetchError as exc:
            group["leak_sites"] = prior.get("leak_sites", [])
            group["profile_status"] = "offline"
            group["profile_error"] = exc.code
            group["profile_checked_at"] = utc_now()
        profiles.append(group)
        sleep(PROFILE_DELAY_SECONDS)

    return {
        "schema_version": 1,
        "source": tracker_url,
        "updated_at": utc_now(),
        "pages_scanned": len(visited_pages),
        "groups": profiles,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tracker-url", default=TRACKER_URL)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args()

    try:
        previous = read_json(args.output, {"groups": []})
        catalog = collect_groups(args.tracker_url, previous=previous)
        write_json_atomic(args.output, catalog)
    except (FetchError, RuntimeError, ValueError) as exc:
        print(f"Group refresh failed: {exc}", file=sys.stderr)
        return 1

    endpoint_count = sum(len(group.get("leak_sites", [])) for group in catalog["groups"])
    print(
        f"Saved {len(catalog['groups'])} groups and {endpoint_count} leak-site endpoints "
        f"to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
