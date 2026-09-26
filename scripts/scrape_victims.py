#!/usr/bin/env python3
"""Collect metadata-only victim listings from WatchGuard-listed leak sites."""

from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
import hashlib
import json
import re
import sys
import time
import unicodedata
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, unquote, urljoin, urlparse, urlunsplit

from html_dom import Element, parse_html
from http_client import FetchError, fetch_html, normalize_url
from json_io import read_json, utc_now, write_json_atomic


ROOT = Path(__file__).resolve().parents[1]
GROUPS_PATH = ROOT / "site" / "data" / "groups.json"
OUTPUT_PATH = ROOT / "site" / "data" / "victims.json"
MAX_CONCURRENCY = 3
FETCH_DEADLINE_SECONDS = 25.0
CRAWL_BUDGET_SECONDS = 90 * 60
REQUEST_DELAY_SECONDS = 0.8
VICTIM_HEADERS = ("victim", "company", "organization", "organisation", "target", "entity")
NAME_HEADERS = {"name", "company name", "victim name", "organization name", "organisation name"}
DATE_HEADERS = ("date", "posted", "published", "added", "reported", "listed", "exposure")
COUNTRY_HEADERS = ("country", "location", "region")
SECTOR_HEADERS = ("sector", "industry", "business")
CARD_CLASS_MARKERS = {"victim", "victim-card", "victim-item", "post", "entry", "attack", "listing", "card"}
GENERIC_TITLES = {
    "home", "about", "contact", "news", "blog", "victims", "victim list",
    "recent victims", "all victims", "load more", "read more",
}
ListingParser = Callable[[str, str], dict]
PARSER_REGISTRY: dict[str, ListingParser] = {}


def register_parser(host_suffix: str, parser: ListingParser) -> None:
    """Register an explicit parser for a leak-site host suffix."""
    suffix = host_suffix.casefold().lstrip(".")
    if not suffix or "/" in suffix:
        raise ValueError("Parser host suffix must be a hostname")
    PARSER_REGISTRY[suffix] = parser


def clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def normalize_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", " ", normalized.casefold()).strip()


def _slug_from_url(value: str) -> str | None:
    parsed = urlparse(value)
    path = unquote(parsed.path).rstrip("/")
    if not path:
        return None
    slug = path.rsplit("/", 1)[-1]
    return slug if slug and slug not in {"index", "home"} else None


def _table_cells(row: Element) -> list[Element]:
    direct = [child for child in row.children if isinstance(child, Element) and child.tag in {"td", "th"}]
    if direct:
        return direct
    return [item for item in row.iter() if item.tag in {"td", "th"}]


def _headers_for_table(table: Element) -> list[str]:
    for row in table.iter("tr"):
        cells = _table_cells(row)
        if cells and any(cell.tag == "th" for cell in cells):
            return [clean_text(cell.text()).casefold() for cell in cells]
    first_row = next(iter(table.iter("tr")), None)
    if first_row:
        cells = _table_cells(first_row)
        values = [clean_text(cell.text()).casefold() for cell in cells]
        if any(value in NAME_HEADERS for value in values):
            return values
    return []


def _header_index(headers: list[str], exact: set[str] | tuple[str, ...], *, allow_name: bool = False) -> int | None:
    for index, value in enumerate(headers):
        if any(term in value for term in exact):
            return index
    if allow_name:
        for index, value in enumerate(headers):
            if value in NAME_HEADERS:
                return index
    return None


def _record_id(row: Element, victim_cell: Element) -> str | None:
    for key in ("data-id", "data-victim-id", "id"):
        value = clean_text(str(row.attrs.get(key) or ""))
        if value and value not in {"", "row"}:
            return value[:160]
    for anchor in victim_cell.iter("a"):
        href = anchor.attrs.get("href")
        if href:
            slug = _slug_from_url(str(href))
            if slug:
                return slug[:160]
    return None


def _records_from_tables(root: Element) -> tuple[bool, list[dict], str | None]:
    for table in root.iter("table"):
        headers = _headers_for_table(table)
        if not headers:
            continue
        victim_index = _header_index(headers, VICTIM_HEADERS, allow_name=True)
        if victim_index is None:
            continue
        has_context = (
            any(any(term in header for term in DATE_HEADERS) for header in headers)
            or any(any(term in header for term in COUNTRY_HEADERS) for header in headers)
            or any(any(term in header for term in SECTOR_HEADERS) for header in headers)
            or any(term in header for header in headers for term in VICTIM_HEADERS)
        )
        if not has_context:
            continue

        date_index = _header_index(headers, DATE_HEADERS)
        country_index = _header_index(headers, COUNTRY_HEADERS)
        sector_index = _header_index(headers, SECTOR_HEADERS)
        records: list[dict] = []
        for row in table.iter("tr"):
            if any(cell.tag == "th" for cell in _table_cells(row)):
                continue
            cells = _table_cells(row)
            if victim_index >= len(cells):
                continue
            organization = clean_text(cells[victim_index].text())
            normalized = normalize_name(organization)
            if not organization or normalized in GENERIC_TITLES or len(organization) > 240:
                continue
            records.append({
                "organization": organization,
                "record_id": _record_id(row, cells[victim_index]),
                "reported_date": clean_text(cells[date_index].text()) if date_index is not None and date_index < len(cells) else None,
                "country": clean_text(cells[country_index].text()) if country_index is not None and country_index < len(cells) else None,
                "sector": clean_text(cells[sector_index].text()) if sector_index is not None and sector_index < len(cells) else None,
            })
        return True, records, "html-table"
    return False, [], None


def _class_tokens(element: Element) -> set[str]:
    return set(str(element.attrs.get("class") or "").casefold().split())


def _card_title(element: Element) -> Element | None:
    for tag in ("h1", "h2", "h3", "h4"):
        heading = next(element.iter(tag), None)
        if heading:
            return heading
    for item in element.iter():
        classes = _class_tokens(item)
        if classes.intersection({"title", "victim-name", "company-name", "organization-name"}):
            return item
    return None


def _records_from_cards(root: Element) -> tuple[bool, list[dict], str | None]:
    records: list[dict] = []
    recognized_empty = False
    seen_names: set[str] = set()
    for item in root.iter():
        classes = _class_tokens(item)
        marked = bool(classes.intersection(CARD_CLASS_MARKERS))
        if not marked:
            continue
        heading_count = sum(1 for tag in ("h1", "h2", "h3", "h4") for _ in item.iter(tag))
        if heading_count > 1:
            continue
        title = _card_title(item)
        if title is None:
            if classes.intersection({"victim", "victim-card", "victim-item"}):
                recognized_empty = True
            continue
        organization = clean_text(title.text())
        normalized = normalize_name(organization)
        if not organization or normalized in GENERIC_TITLES or len(organization) > 240:
            continue
        if normalized in seen_names:
            continue
        seen_names.add(normalized)
        time_node = next(item.iter("time"), None)
        date_value = None
        if time_node:
            date_value = clean_text(str(time_node.attrs.get("datetime") or time_node.text())) or None
        if date_value is None:
            for child in item.iter():
                classes = _class_tokens(child)
                if classes.intersection({"date", "published", "posted", "timestamp"}):
                    date_value = clean_text(child.text()) or None
                    break
        country = None
        sector = None
        for child in item.iter():
            classes = _class_tokens(child)
            if country is None and classes.intersection({"country", "location", "region"}):
                country = clean_text(child.text()) or None
            if sector is None and classes.intersection({"sector", "industry"}):
                sector = clean_text(child.text()) or None
        identity = clean_text(str(item.attrs.get("data-id") or item.attrs.get("id") or "")) or None
        if identity is None:
            for anchor in title.iter("a"):
                href = anchor.attrs.get("href")
                if href:
                    identity = _slug_from_url(str(href))
                    if identity:
                        break
        records.append({
            "organization": organization,
            "record_id": identity,
            "reported_date": date_value,
            "country": country,
            "sector": sector,
        })
    return bool(records) or recognized_empty, records, "html-cards" if records or recognized_empty else None


def _same_source_host(candidate: str, base_url: str) -> bool:
    try:
        return (urlparse(candidate).hostname or "").casefold() == (urlparse(base_url).hostname or "").casefold()
    except ValueError:
        return False


def extract_pagination_urls(root: Element, page_url: str) -> list[str]:
    candidates: dict[str, str] = {}
    parsed_base = urlparse(page_url)
    base_path = parsed_base.path.rstrip("/")
    for anchor in root.iter("a"):
        href = anchor.attrs.get("href")
        if not href:
            continue
        absolute = urljoin(page_url, str(href))
        parsed = urlparse(absolute)
        if not _same_source_host(absolute, page_url):
            continue
        if parsed.scheme not in {"http", "https"}:
            continue
        if base_path and parsed.path.rstrip("/") != base_path and not parsed.path.startswith(base_path + "/"):
            continue

        rel = str(anchor.attrs.get("rel") or "").casefold().split()
        pagination_context = any(
            parent.has_class("pagination") or parent.has_class("pager")
            for parent in anchor.ancestors()
        )
        query = parse_qs(parsed.query)
        page_query = any(key.casefold() in {"page", "p", "offset"} for key in query)
        label = clean_text(anchor.text()).casefold()
        is_next = "next" in rel or label in {"next", "›", "»", "→", "older"}
        if not (is_next or pagination_context or page_query):
            continue
        key = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/") or "/", parsed.query, ""))
        if key.rstrip("/") != page_url.rstrip("/"):
            candidates[key] = absolute
    return list(candidates.values())


def parse_listing(markup: str, page_url: str) -> dict:
    root = parse_html(markup)
    hostname = (urlparse(page_url).hostname or "").casefold()
    for suffix, parser in sorted(PARSER_REGISTRY.items(), key=lambda item: len(item[0]), reverse=True):
        if hostname == suffix or hostname.endswith("." + suffix):
            adapted = parser(markup, page_url)
            if adapted.get("recognized"):
                pagination = list(adapted.get("pagination_urls") or [])
                pagination.extend(extract_pagination_urls(root, page_url))
                return {
                    **adapted,
                    "pagination_urls": list(dict.fromkeys(pagination)),
                }
    recognized, records, parser_name = _records_from_tables(root)
    if not recognized:
        recognized, records, parser_name = _records_from_cards(root)
    return {
        "recognized": recognized,
        "records": records,
        "parser": parser_name,
        "pagination_urls": extract_pagination_urls(root, page_url),
    }


def _canonical_source_url(url: str) -> str:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    query = "&".join(sorted(parsed.query.split("&"))) if parsed.query else ""
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/") or "/", query, ""))


def source_id_for(url: str, group_id: str = "") -> str:
    identity = str(group_id).casefold() + "\0" + _canonical_source_url(url)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def sighting_id_for(group_id: str, source_id: str, record: dict) -> str:
    record_id = clean_text(str(record.get("record_id") or ""))
    stable_identity = "record:" + record_id.casefold() if record_id else "name:" + normalize_name(
        str(record.get("organization") or "")
    )
    material = f"{group_id.casefold()}\0{source_id}\0{stable_identity}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def _dedupe_records(records: list[dict]) -> list[dict]:
    result: dict[str, dict] = {}
    for record in records:
        key = normalize_name(str(record.get("organization") or ""))
        if not key:
            continue
        existing = result.get(key)
        if existing is None:
            result[key] = record
            continue
        for field in ("record_id", "reported_date", "country", "sector"):
            if not existing.get(field) and record.get(field):
                existing[field] = record[field]
    return list(result.values())


def crawl_site(
    source_url: str,
    *,
    group_id: str = "",
    fetcher=fetch_html,
    deadline_seconds: float = FETCH_DEADLINE_SECONDS,
) -> dict:
    """Fetch and parse exactly the initial listing page for a source."""
    try:
        normalized_source = normalize_url(source_url)
        source_id = source_id_for(normalized_source, group_id)
        source_host = (urlparse(normalized_source).hostname or "").lower()
    except FetchError as exc:
        return {
            "source_id": hashlib.sha256(
                (str(group_id).casefold() + "\0" + str(source_url)).encode("utf-8")
            ).hexdigest()[:20],
            "source_host": "",
            "status": "unsupported",
            "error": exc.code,
            "error_type": getattr(exc, "cause_type", None),
            "pages_scanned": 0,
            "records": [],
            "parser": None,
            "http_status": getattr(exc, "http_status", None),
        }

    try:
        response = fetcher(normalized_source, total_timeout=deadline_seconds)
    except FetchError as exc:
        unsupported = exc.code in {
            "invalid_url", "unsupported_scheme", "unsupported_content_type",
            "blocked_private_target", "unsupported_layout",
        }
        return {
            "source_id": source_id,
            "source_host": source_host,
            "status": "unsupported" if unsupported else "offline",
            "error": exc.code,
            "error_type": getattr(exc, "cause_type", None),
            "pages_scanned": 0,
            "records": [],
            "parser": None,
            "http_status": getattr(exc, "http_status", None),
        }
    except Exception as exc:
        return {
            "source_id": source_id,
            "source_host": source_host,
            "status": "offline",
            "error": "fetch_error",
            "error_type": type(exc).__name__,
            "pages_scanned": 0,
            "records": [],
            "parser": None,
            "http_status": None,
        }

    response_host = (urlparse(response.url).hostname or "").casefold()
    error: str | None = None
    error_type: str | None = None
    parsed_result: dict | None = None
    if not response_host:
        error = "invalid_response_url"
    elif response_host != source_host:
        error = "redirect_host_changed"
    else:
        try:
            parsed_result = parse_listing(response.body, response.url)
            if not parsed_result["recognized"]:
                error = "unsupported_layout"
        except Exception as exc:
            error = "parser_error"
            error_type = type(exc).__name__

    if error:
        return {
            "source_id": source_id,
            "source_host": response_host or source_host,
            "status": "unsupported" if error == "unsupported_layout" else "offline",
            "error": error,
            "error_type": error_type,
            "pages_scanned": 1 if response_host else 0,
            "records": [],
            "parser": None,
            "http_status": getattr(response, "status_code", None),
        }

    return {
        "source_id": source_id,
        "source_host": response_host,
        "status": "ok",
        "error": None,
        "error_type": None,
        "pages_scanned": 1,
        "records": _dedupe_records(parsed_result["records"]),
        "parser": parsed_result.get("parser"),
        "http_status": getattr(response, "status_code", None),
    }

def merge_source_result(
    existing_sightings: list[dict],
    group: dict,
    source: dict,
    result: dict,
    observed_at: str,
) -> list[dict]:
    """Merge a source crawl into append-only history and update listing state."""
    group_id = str(group.get("group_id") or "unknown")
    source_id = str(result["source_id"])
    existing_by_id = {
        item["id"]: dict(item)
        for item in existing_sightings
        if isinstance(item, dict) and item.get("id")
    }
    current_ids: set[str] = set()
    profile_url = str(group.get("profile_url") or "")

    for record in result.get("records", []):
        organization = clean_text(str(record.get("organization") or ""))
        if not organization:
            continue
        sighting_id = sighting_id_for(group_id, source_id, record)
        current_ids.add(sighting_id)
        old = existing_by_id.get(sighting_id, {})
        sighting = {
            **old,
            "id": sighting_id,
            "group_id": group_id,
            "group_name": str(group.get("name") or group_id),
            "organization": organization,
            "reported_date": clean_text(str(record.get("reported_date") or "")) or old.get("reported_date"),
            "country": clean_text(str(record.get("country") or "")) or old.get("country"),
            "sector": clean_text(str(record.get("sector") or "")) or old.get("sector"),
            "first_seen_at": old.get("first_seen_at") or observed_at,
            "last_seen_at": observed_at,
            "listing_state": "listed",
            "source_id": source_id,
            "source_host": result.get("source_host") or "",
            "watchguard_profile_url": profile_url,
        }
        existing_by_id[sighting_id] = sighting

    for sighting_id, sighting in existing_by_id.items():
        if sighting.get("group_id") != group_id or sighting.get("source_id") != source_id:
            continue
        if sighting_id in current_ids:
            continue
        # A one-page check cannot establish that a historical listing was
        # removed, so absence from page one always remains unknown.
        sighting["listing_state"] = "unknown"

    return sorted(
        existing_by_id.values(),
        key=lambda item: (
            str(item.get("last_seen_at") or ""),
            str(item.get("group_name") or "").casefold(),
            str(item.get("organization") or "").casefold(),
        ),
        reverse=True,
    )


def _group_status(source_results: list[dict], group_status: str = "active") -> str:
    if group_status.casefold() != "active":
        return "skipped_inactive"
    if not source_results:
        return "no_source"
    statuses = {item["status"] for item in source_results}
    if statuses == {"ok"}:
        return "ok"
    if statuses == {"skipped_budget"}:
        return "skipped_budget"
    if statuses == {"skipped_unscoped_catalog"}:
        return "skipped_unscoped_catalog"
    if statuses == {"offline"}:
        return "offline"
    if statuses == {"unsupported"}:
        return "unsupported"
    if statuses == {"skipped_inactive"}:
        return "skipped_inactive"
    return "partial"


def _safe_source_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").casefold()
    except ValueError:
        return ""


def _emit(message: str) -> None:
    print(message, flush=True)


def crawl_catalog(
    catalog: dict,
    previous: dict | None = None,
    *,
    fetcher=fetch_html,
    budget_seconds: float = CRAWL_BUDGET_SECONDS,
    fetch_deadline_seconds: float = FETCH_DEADLINE_SECONDS,
    request_delay_seconds: float = REQUEST_DELAY_SECONDS,
    max_concurrency: int = MAX_CONCURRENCY,
    sleep=time.sleep,
) -> dict:
    """Crawl active first-page sources, deduplicating URLs and retaining history."""
    groups = catalog.get("groups")
    if not isinstance(groups, list):
        raise ValueError("Group catalog has no groups list")
    if not groups:
        raise ValueError("Group catalog is empty; refresh it before crawling victims")

    previous = previous or {}
    run_at = utc_now()
    crawl_started = time.monotonic()
    deadline = crawl_started + max(0.0, float(budget_seconds))
    sightings = [dict(item) for item in previous.get("sightings", []) if isinstance(item, dict)]
    source_records: dict[str, dict] = {
        str(item["source_id"]): dict(item)
        for item in previous.get("sources", [])
        if isinstance(item, dict) and item.get("source_id")
    }
    current_source_ids: set[str] = set()
    active_urls: dict[str, dict] = {}
    group_by_id: dict[str, dict] = {}
    group_source_ids: dict[str, list[str]] = {}
    active_group_ids: set[str] = set()
    inactive_group_ids: set[str] = set()
    active_assignment_count = 0

    for group in groups:
        if not isinstance(group, dict) or not group.get("group_id"):
            continue
        group_id = str(group["group_id"])
        group_by_id[group_id] = group
        group_source_ids[group_id] = []
        if str(group.get("status") or "unknown").casefold() == "active":
            active_group_ids.add(group_id)
        else:
            inactive_group_ids.add(group_id)

        sources = group.get("leak_sites") or []
        for source in sources:
            if not isinstance(source, dict) or not source.get("url"):
                continue
            raw_url = str(source["url"])
            try:
                canonical_url = _canonical_source_url(raw_url)
                source_id = source_id_for(canonical_url, group_id)
                host = _safe_source_host(canonical_url)
                url_error = None
            except FetchError as exc:
                canonical_url = ""
                source_id = hashlib.sha256((group_id.casefold() + "\0" + raw_url).encode("utf-8")).hexdigest()[:20]
                host = ""
                url_error = exc.code

            if source_id in group_source_ids[group_id]:
                continue
            current_source_ids.add(source_id)
            group_source_ids[group_id].append(source_id)
            if group_id not in active_group_ids:
                prior = source_records.get(source_id, {})
                record = {
                    **prior,
                    "source_id": source_id,
                    "group_id": group_id,
                    "group_name": str(group.get("name") or group_id),
                    "source_host": prior.get("source_host") or host,
                    "status": "skipped_inactive",
                    "status_updated_at": run_at,
                    "pages_scanned": 0,
                    "victims_found": 0,
                    "error": None,
                    "watchguard_profile_url": str(group.get("profile_url") or ""),
                }
                source_records[source_id] = record
                for sighting in sightings:
                    if sighting.get("source_id") == source_id:
                        sighting["listing_state"] = "unknown"
                continue

            if group.get("leak_sites_scope") != "extortion_links":
                prior = source_records.get(source_id, {})
                source_records[source_id] = {
                    **prior,
                    "source_id": source_id,
                    "group_id": group_id,
                    "group_name": str(group.get("name") or group_id),
                    "source_host": prior.get("source_host") or host,
                    "status": "skipped_unscoped_catalog",
                    "status_updated_at": run_at,
                    "pages_scanned": 0,
                    "victims_found": 0,
                    "error": "missing_extortion_scope",
                    "watchguard_profile_url": str(group.get("profile_url") or ""),
                }
                for sighting in sightings:
                    if sighting.get("source_id") == source_id:
                        sighting["listing_state"] = "unknown"
                _emit(
                    f"source_skipped group_id={group_id} source_id={source_id} host={host or 'unknown'} "
                    "elapsed_seconds=0.00 status=skipped_unscoped_catalog error=missing_extortion_scope"
                )
                continue

            active_assignment_count += 1
            if url_error:
                result = {
                    "source_id": source_id,
                    "source_host": host,
                    "status": "unsupported",
                    "error": url_error,
                    "error_type": None,
                    "http_status": None,
                    "pages_scanned": 0,
                    "records": [],
                    "parser": None,
                }
                completed_at = utc_now()
                sightings = merge_source_result(sightings, group, source, result, completed_at)
                source_records[source_id] = {
                    "source_id": source_id,
                    "group_id": group_id,
                    "group_name": str(group.get("name") or group_id),
                    "source_host": host,
                    "status": result["status"],
                    "checked_at": completed_at,
                    "status_updated_at": completed_at,
                    "pages_scanned": 0,
                    "victims_found": 0,
                    "parser": None,
                    "error": url_error,
                    "error_type": None,
                    "http_status": None,
                    "watchguard_profile_url": str(group.get("profile_url") or ""),
                }
                _emit(
                    f"source_error group_id={group_id} source_id={source_id} host=unknown "
                    f"elapsed_seconds=0.00 status=unsupported error={url_error} progress=local_validation"
                )
                continue

            entry = active_urls.setdefault(canonical_url, {
                "url": canonical_url,
                "host": host,
                "associations": [],
            })
            if not any(item["source_id"] == source_id for item in entry["associations"]):
                entry["associations"].append({"group": group, "source": source, "source_id": source_id})

    pending = [active_urls[key] for key in sorted(active_urls)]
    unique_url_count = len(pending)
    worker_count = max(1, min(3, int(max_concurrency)))
    _emit(
        "crawl_started "
        f"active_groups={len(active_group_ids)} non_active_groups={len(inactive_group_ids)} "
        f"eligible_group_sources={active_assignment_count} unique_urls={unique_url_count} "
        f"workers={worker_count} fetch_deadline_seconds={fetch_deadline_seconds:g} "
        f"crawl_budget_seconds={max(0.0, float(budget_seconds)):g}"
    )

    completed_unique = 0
    last_host_start: dict[str, float] = {}
    in_flight: dict[Future, tuple[dict, float]] = {}
    budget_skipped: list[dict] = []

    def store_completed(entry: dict, result: dict, started_at: float) -> None:
        nonlocal sightings, completed_unique
        completed_unique += 1
        elapsed = time.monotonic() - started_at
        completed_at = utc_now()
        associations = entry["associations"]
        group_ids = ",".join(str(item["group"]["group_id"]) for item in associations)
        association_source_ids = ",".join(item["source_id"] for item in associations)
        for association in associations:
            group = association["group"]
            source = association["source"]
            source_id = association["source_id"]
            attributed_result = {**result, "source_id": source_id}
            sightings = merge_source_result(sightings, group, source, attributed_result, completed_at)
            source_records[source_id] = {
                "source_id": source_id,
                "group_id": str(group["group_id"]),
                "group_name": str(group.get("name") or group["group_id"]),
                "source_host": result.get("source_host") or entry["host"],
                "status": result["status"],
                "checked_at": completed_at,
                "status_updated_at": completed_at,
                "pages_scanned": result.get("pages_scanned", 0),
                "victims_found": len(result.get("records", [])),
                "parser": result.get("parser"),
                "error": result.get("error"),
                "error_type": result.get("error_type"),
                "http_status": result.get("http_status"),
                "watchguard_profile_url": str(group.get("profile_url") or ""),
            }
        detail = (
            f"http_status={result.get('http_status')}"
            if result.get("http_status") is not None
            else f"error={result.get('error') or 'unknown'}"
        )
        if result.get("error_type"):
            detail += f" error_type={result['error_type']}"
        _emit(
            f"source_complete progress={completed_unique}/{unique_url_count} "
            f"group_ids={group_ids} source_ids={association_source_ids} host={entry['host'] or 'unknown'} "
            f"elapsed_seconds={elapsed:.2f} status={result['status']} {detail} "
            f"pages={result.get('pages_scanned', 0)} victims_count={len(result.get('records', []))}"
        )

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="victim-crawl") as executor:
        while pending or in_flight:
            now = time.monotonic()
            budget_remaining = deadline - now
            if budget_remaining <= 0 and pending:
                budget_skipped.extend(pending)
                pending.clear()
            while pending and len(in_flight) < worker_count and budget_remaining > 0:
                if time.monotonic() >= deadline:
                    budget_remaining = 0
                    break
                ready_index = None
                wait_for_host = None
                for index, item in enumerate(pending):
                    available_at = last_host_start.get(item["host"], float("-inf")) + max(0.0, request_delay_seconds)
                    delay_left = available_at - now
                    if delay_left <= 0:
                        ready_index = index
                        break
                    wait_for_host = delay_left if wait_for_host is None else min(wait_for_host, delay_left)
                if ready_index is None:
                    break
                entry = pending.pop(ready_index)
                started_at = time.monotonic()
                last_host_start[entry["host"]] = started_at
                group_ids = ",".join(str(item["group"]["group_id"]) for item in entry["associations"])
                source_ids = ",".join(item["source_id"] for item in entry["associations"])
                _emit(
                    f"source_start progress={completed_unique + len(in_flight) + 1}/{unique_url_count} "
                    f"group_ids={group_ids} source_ids={source_ids} host={entry['host'] or 'unknown'}"
                )
                future = executor.submit(
                    crawl_site,
                    entry["url"],
                    fetcher=fetcher,
                    deadline_seconds=fetch_deadline_seconds,
                )
                in_flight[future] = (entry, started_at)
                now = time.monotonic()
                budget_remaining = deadline - now

            if not pending and not in_flight:
                break

            timeout_candidates = []
            budget_remaining = deadline - time.monotonic()
            if pending and budget_remaining > 0:
                timeout_candidates.append(budget_remaining)
                for item in pending:
                    available_at = last_host_start.get(item["host"], float("-inf")) + max(0.0, request_delay_seconds)
                    if available_at > time.monotonic():
                        timeout_candidates.append(available_at - time.monotonic())
            wait_timeout = min(timeout_candidates) if timeout_candidates else None
            if in_flight:
                done, _not_done = wait(tuple(in_flight), timeout=wait_timeout, return_when=FIRST_COMPLETED)
                for future in done:
                    entry, started_at = in_flight.pop(future)
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "status": "offline", "error": "worker_error",
                            "error_type": type(exc).__name__, "http_status": None,
                            "pages_scanned": 0, "records": [], "parser": None,
                            "source_host": entry["host"],
                        }
                    store_completed(entry, result, started_at)
            elif pending:
                delay = wait_timeout if wait_timeout is not None else 0
                if delay > 0:
                    sleep(delay)

    budget_exhausted = bool(budget_skipped)
    for entry in budget_skipped:
        for association in entry["associations"]:
            group = association["group"]
            source = association["source"]
            source_id = association["source_id"]
            prior = source_records.get(source_id, {})
            source_records[source_id] = {
                **prior,
                "source_id": source_id,
                "group_id": str(group["group_id"]),
                "group_name": str(group.get("name") or group["group_id"]),
                "source_host": prior.get("source_host") or entry["host"],
                "status": "skipped_budget",
                "status_updated_at": utc_now(),
                "pages_scanned": 0,
                "victims_found": 0,
                "error": None,
                "error_type": None,
                "http_status": None,
                "watchguard_profile_url": str(group.get("profile_url") or ""),
            }
            for sighting in sightings:
                if sighting.get("source_id") == source_id:
                    sighting["listing_state"] = "unknown"
    if budget_exhausted:
        _emit(
            f"crawl_budget_exhausted completed_unique={completed_unique} "
            f"unique_urls={unique_url_count} skipped_unique={len(budget_skipped)} "
            f"budget_seconds={max(0.0, float(budget_seconds)):g}"
        )

    for source_id, source_record in list(source_records.items()):
        if source_id in current_source_ids:
            continue
        source_record["status"] = "not_in_catalog"
        source_record["status_updated_at"] = utc_now()
        source_records[source_id] = source_record
        for sighting in sightings:
            if sighting.get("source_id") == source_id:
                sighting["listing_state"] = "unknown"

    group_summaries: list[dict] = []
    for group_id, group in group_by_id.items():
        result_records = [source_records[item] for item in group_source_ids[group_id] if item in source_records]
        eligibility = "active" if group_id in active_group_ids else "non_active"
        group_summaries.append({
            "group_id": group_id,
            "name": str(group.get("name") or group_id),
            "watchguard_profile_url": str(group.get("profile_url") or ""),
            "eligibility": eligibility,
            "status": _group_status(result_records, str(group.get("status") or "unknown")),
            "source_issue": group.get("leak_sites_status") or (
                "catalog_missing_extortion_scope"
                if group.get("leak_sites") and group.get("leak_sites_scope") != "extortion_links"
                else None
            ),
            "checked_at": run_at,
            "sources_total": len(result_records),
            "sources_ok": sum(item.get("status") == "ok" for item in result_records),
            "sources_skipped": sum(str(item.get("status", "")).startswith("skipped_") for item in result_records),
        })

    elapsed = time.monotonic() - crawl_started
    final_counts: dict[str, int] = {}
    for source_id in current_source_ids:
        status = source_records.get(source_id, {}).get("status", "unknown")
        final_counts[status] = final_counts.get(status, 0) + 1
    counts_text = ",".join(f"{key}={value}" for key, value in sorted(final_counts.items())) or "none"
    _emit(
        f"crawl_finished elapsed_seconds={elapsed:.2f} completed_unique={completed_unique}/{unique_url_count} "
        f"budget_exhausted={str(budget_exhausted).lower()} source_statuses={counts_text} "
        f"sightings={len(sightings)}"
    )

    return {
        "schema_version": 1,
        "updated_at": utc_now(),
        "crawl_started_at": run_at,
        "crawl_elapsed_seconds": round(elapsed, 2),
        "crawl_budget_seconds": max(0, int(budget_seconds)),
        "crawl_partial": budget_exhausted,
        "source_catalog_updated_at": catalog.get("updated_at"),
        "groups": sorted(group_summaries, key=lambda item: item["name"].casefold()),
        "sources": sorted(source_records.values(), key=lambda item: (item["group_name"].casefold(), item["source_host"])),
        "sightings": sorted(
            sightings,
            key=lambda item: (
                str(item.get("last_seen_at") or ""),
                str(item.get("group_name") or "").casefold(),
                str(item.get("organization") or "").casefold(),
            ),
            reverse=True,
        ),
    }

def _catalog_needs_tor(catalog: dict) -> bool:
    for group in catalog.get("groups", []):
        if (
            not isinstance(group, dict)
            or str(group.get("status") or "unknown").casefold() != "active"
            or group.get("leak_sites_scope") != "extortion_links"
        ):
            continue
        for source in group.get("leak_sites", []) if isinstance(group, dict) else []:
            if isinstance(source, dict) and ".onion" in str(source.get("url") or "").casefold():
                return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--groups", type=Path, default=GROUPS_PATH)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument(
        "--needs-tor",
        action="store_true",
        help="exit 0 when the catalog contains onion sources, otherwise exit 1",
    )
    args = parser.parse_args()

    try:
        catalog = read_json(args.groups, {"groups": []})
        if args.needs_tor:
            return 0 if _catalog_needs_tor(catalog) else 1
        previous = read_json(args.output, {"sightings": [], "sources": []})
        result = crawl_catalog(catalog, previous)
        write_json_atomic(args.output, result)
    except (FetchError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Victim scrape failed: {exc}", file=sys.stderr)
        return 1

    status_counts: dict[str, int] = {}
    for source in result["sources"]:
        status_counts[source["status"]] = status_counts.get(source["status"], 0) + 1
    summary = ", ".join(f"{key}={value}" for key, value in sorted(status_counts.items())) or "no sources"
    if result.get("crawl_partial"):
        print(
            "::warning::The 90-minute crawl budget was reached; completed sightings were saved "
            "and remaining sources were marked skipped_budget.",
            flush=True,
        )
    print(
        f"Saved {len(result['sightings'])} historical sightings from "
        f"{len(result['sources'])} sources ({summary}) to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
