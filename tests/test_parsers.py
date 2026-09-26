from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import refresh_groups
import scrape_victims
from http_client import FetchError, _validate_public_target, normalize_url


FIXTURES = ROOT / "tests" / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class WatchGuardParserTests(unittest.TestCase):
    def test_tracker_page_extracts_group_metadata_and_pagination(self) -> None:
        groups, pages = refresh_groups.parse_tracker_page(
            fixture("watchguard-tracker-page-0.html"),
            refresh_groups.TRACKER_URL,
        )
        self.assertEqual([item["name"] for item in groups], ["Endzone", "Old Group"])
        self.assertEqual(groups[0]["status"], "active")
        self.assertEqual(groups[0]["types"], "Data Broker")
        self.assertEqual(groups[0]["first_seen"], "September 2026")
        self.assertEqual(groups[1]["status"], "inactive")
        self.assertTrue(any("?page=1" in page for page in pages))

    def test_profile_keeps_web_and_onion_sites_but_ignores_messaging(self) -> None:
        sites = refresh_groups.extract_leak_sites(
            fixture("watchguard-profile.html"),
            "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/endzone",
        )
        urls = {item["url"] for item in sites}
        self.assertIn("https://leak.example.invalid/", urls)
        self.assertIn("http://aaaaaaaaaaaaaaaa.onion/", urls)
        self.assertFalse(any("t.me" in value for value in urls))
        self.assertFalse(any("mailto:" in value for value in urls))
        self.assertFalse(any("widencollective" in value for value in urls))
        self.assertFalse(any("unrelated.example.invalid" in value for value in urls))

    def test_profile_without_extortion_section_returns_no_sources(self) -> None:
        self.assertEqual(
            refresh_groups.extract_leak_sites(
                '<a href="https://not-a-leak.invalid/">Contact</a>',
                "https://www.watchguard.com/profile",
            ),
            [],
        )

    def test_profile_extracts_watchguard_non_heading_extortion_label(self) -> None:
        markup = """<main>
          <div>Extortion Links MEDIUM LINK</div>
          <div><p>Telegram</p><p>https://t.me/group</p></div>
          <div><p>TOR</p><p>cccccccccccccccc.onion</p></div>
          <div>Extortion Types Direct Extortion Double Extortion Communication MEDIUM IDENTIFIER</div>
          <div><p>Email</p><p>https://mail.example.invalid/contact</p></div>
          <h2>Known Victims</h2>
          <a href="https://watchguard.widencollective.com/brand">Brand</a>
        </main>"""
        section_found, _anchors, _visible_text = refresh_groups._extortion_links_content(
            refresh_groups.parse_html(markup)
        )
        urls = {
            item["url"]
            for item in refresh_groups.extract_leak_sites(
                markup,
                "https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/group",
            )
        }
        self.assertTrue(section_found)
        self.assertIn("http://cccccccccccccccc.onion/", urls)
        self.assertFalse(any("t.me" in value for value in urls))
        self.assertFalse(any("mail.example.invalid" in value for value in urls))
        self.assertFalse(any("widencollective" in value for value in urls))

    def test_catalog_refuses_to_replace_catalog_when_active_sources_all_disappear(self) -> None:
        index = '<table><tr><th>Status</th><th>Group</th></tr><tr><td>Active</td><td><a href="/wgrd-security-hub/ransomware-tracker/endzone">Endzone</a></td></tr></table>'
        profile = '<main><h2>Communication</h2><a href="https://contact.example.invalid/">Contact</a></main>'

        def fake_fetch(url: str, **_kwargs) -> SimpleNamespace:
            body = index if "ransomware-tracker" in url and not url.rstrip("/").endswith("endzone") else profile
            return SimpleNamespace(url=url, body=body)

        with self.assertRaisesRegex(RuntimeError, "No leak-site endpoints were found for active groups"):
            refresh_groups.collect_groups(fetcher=fake_fetch, sleep=lambda _delay: None)

    def test_catalog_walks_all_tracker_pages_and_profiles(self) -> None:
        index_0 = fixture("watchguard-tracker-page-0.html")
        index_1 = fixture("watchguard-tracker-page-1.html")
        profile = fixture("watchguard-profile.html")
        calls: list[str] = []

        def fake_fetch(url: str, **_kwargs) -> SimpleNamespace:
            calls.append(url)
            if "page=1" in url:
                body = index_1
            elif url.rstrip("/").endswith("ransomware-tracker"):
                body = index_0
            else:
                body = profile
            return SimpleNamespace(url=url, body=body)

        result = refresh_groups.collect_groups(
            fetcher=fake_fetch,
            sleep=lambda _delay: None,
        )
        self.assertEqual(result["pages_scanned"], 2)
        self.assertEqual({group["group_id"] for group in result["groups"]}, {"endzone", "old-group", "blue-team"})
        self.assertEqual(next(group for group in result["groups"] if group["group_id"] == "endzone")["leak_sites_scope"], "extortion_links")
        self.assertGreaterEqual(len(calls), 5)


class VictimParserTests(unittest.TestCase):
    def test_tor_is_required_only_for_active_onion_sources(self) -> None:
        self.assertFalse(scrape_victims._catalog_needs_tor({"groups": [
            {"status": "unknown", "leak_sites": [{"url": "http://aaaaaaaaaaaaaaaa.onion/"}]},
        ]}))
        self.assertFalse(scrape_victims._catalog_needs_tor({"groups": [
            {"status": "active", "leak_sites": [{"url": "http://aaaaaaaaaaaaaaaa.onion/"}]},
        ]}))
        self.assertTrue(scrape_victims._catalog_needs_tor({"groups": [
            {"status": "active", "leak_sites_scope": "extortion_links", "leak_sites": [{"url": "http://aaaaaaaaaaaaaaaa.onion/"}]},
        ]}))

    def test_table_parser_extracts_metadata_and_pagination(self) -> None:
        parsed = scrape_victims.parse_listing(
            fixture("leak-table-page-1.html"),
            "https://leak.example.invalid/",
        )
        self.assertTrue(parsed["recognized"])
        self.assertEqual(parsed["parser"], "html-table")
        self.assertEqual(parsed["records"][0]["organization"], "Alpha Research")
        self.assertEqual(parsed["records"][0]["country"], "Australia")
        self.assertEqual(parsed["records"][0]["reported_date"], "2026-09-20")
        self.assertTrue(any("?page=2" in page for page in parsed["pagination_urls"]))

    def test_card_parser_extracts_records_and_metadata(self) -> None:
        parsed = scrape_victims.parse_listing(
            fixture("leak-cards.html"),
            "https://leak.example.invalid/",
        )
        self.assertTrue(parsed["recognized"])
        self.assertEqual(parsed["parser"], "html-cards")
        self.assertEqual(len(parsed["records"]), 2)
        self.assertEqual(parsed["records"][0]["sector"], "Manufacturing")

    def test_crawl_reads_one_page_only(self) -> None:
        page_1 = fixture("leak-table-page-1.html")
        calls: list[str] = []

        def fake_fetch(url: str, **_kwargs) -> SimpleNamespace:
            calls.append(url)
            return SimpleNamespace(url=url, body=page_1, status_code=200)

        result = scrape_victims.crawl_site(
            "https://leak.example.invalid/",
            fetcher=fake_fetch,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["pages_scanned"], 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual({row["organization"] for row in result["records"]}, {"Alpha Research"})

    def test_fetch_deadline_is_passed_to_fetcher_and_reported(self) -> None:
        observed: dict[str, float] = {}

        def timed_out_fetch(url: str, **kwargs) -> SimpleNamespace:
            observed.update(kwargs)
            raise FetchError("deadline_exceeded", cause_type="ReadTimeout")

        result = scrape_victims.crawl_site(
            "https://slow.example.invalid/",
            fetcher=timed_out_fetch,
            deadline_seconds=25,
        )
        self.assertEqual(observed["total_timeout"], 25)
        self.assertEqual(result["status"], "offline")
        self.assertEqual(result["error"], "deadline_exceeded")
        self.assertEqual(result["error_type"], "ReadTimeout")

    def test_sighting_history_updates_and_tracks_removed_or_unknown_records(self) -> None:
        group = {
            "group_id": "group-a",
            "name": "Group A",
            "profile_url": "https://www.watchguard.com/profile",
        }
        source = {"url": "https://leak.example.invalid/"}
        result = {
            "source_id": scrape_victims.source_id_for(source["url"], "group-a"),
            "source_host": "leak.example.invalid",
            "status": "ok",
            "records": [
                {
                    "organization": "Alpha Research",
                    "record_id": "alpha",
                    "reported_date": "2026-09-20",
                    "country": "Australia",
                    "sector": "Technology",
                },
                {
                    "organization": "Northstar Health",
                    "record_id": "northstar",
                    "reported_date": "2026-09-22",
                    "country": "New Zealand",
                    "sector": "Healthcare",
                },
            ],
        }
        first = scrape_victims.merge_source_result([], group, source, result, "2026-09-25T00:00:00Z")
        repeated = dict(result, records=[result["records"][0]])
        second = scrape_victims.merge_source_result(first, group, source, repeated, "2026-09-26T00:00:00Z")

        alpha = next(item for item in second if item["organization"] == "Alpha Research")
        northstar = next(item for item in second if item["organization"] == "Northstar Health")
        self.assertEqual(alpha["first_seen_at"], "2026-09-25T00:00:00Z")
        self.assertEqual(alpha["last_seen_at"], "2026-09-26T00:00:00Z")
        self.assertEqual(alpha["listing_state"], "listed")
        self.assertEqual(northstar["listing_state"], "unknown")

        offline = dict(result, status="offline", records=[])
        third = scrape_victims.merge_source_result(second, group, source, offline, "2026-09-27T00:00:00Z")
        self.assertTrue(all(item["listing_state"] == "unknown" for item in third))
        self.assertEqual(
            next(item for item in third if item["organization"] == "Alpha Research")["last_seen_at"],
            "2026-09-26T00:00:00Z",
        )

    def test_source_urls_reject_private_targets_and_normalize_onion(self) -> None:
        with self.assertRaises(FetchError):
            _validate_public_target("http://127.0.0.1/")
        with self.assertRaises(FetchError):
            _validate_public_target("http://169.254.169.254/latest/meta-data/")
        with self.assertRaises(FetchError):
            normalize_url("http://[invalid-host/")
        self.assertEqual(
            normalize_url("aaaaaaaaaaaaaaaa.onion"),
            "http://aaaaaaaaaaaaaaaa.onion/",
        )

    def test_unrecognized_layout_is_not_treated_as_empty_success(self) -> None:
        parsed = scrape_victims.parse_listing(
            "<html><body><h1>Welcome</h1><a href='/files.zip'>Download</a></body></html>",
            "https://leak.example.invalid/",
        )
        self.assertFalse(parsed["recognized"])
        self.assertEqual(parsed["records"], [])

    def test_catalog_crawls_active_groups_and_deduplicates_shared_urls(self) -> None:
        calls: list[str] = []

        def fake_fetch(url: str, **_kwargs) -> SimpleNamespace:
            calls.append(url)
            return SimpleNamespace(url=url, body=fixture("leak-table-page-1.html"), status_code=200)

        catalog = {"groups": [
            {"group_id": "active-one", "name": "Active One", "status": "active", "leak_sites_scope": "extortion_links", "profile_url": "https://www.watchguard.com/a", "leak_sites": [{"url": "https://leak.example.invalid/"}]},
            {"group_id": "active-two", "name": "Active Two", "status": "active", "leak_sites_scope": "extortion_links", "profile_url": "https://www.watchguard.com/b", "leak_sites": [{"url": "https://leak.example.invalid/"}]},
            {"group_id": "unknown-one", "name": "Unknown One", "status": "unknown", "profile_url": "https://www.watchguard.com/c", "leak_sites": [{"url": "https://inactive.example.invalid/"}]},
        ]}
        result = scrape_victims.crawl_catalog(
            catalog,
            fetcher=fake_fetch,
            budget_seconds=10,
            request_delay_seconds=0,
        )

        self.assertEqual(calls, ["https://leak.example.invalid/"])
        self.assertEqual(len(result["sightings"]), 2)
        self.assertEqual({item["group_id"] for item in result["sightings"]}, {"active-one", "active-two"})
        source_states = {item["group_id"]: item["status"] for item in result["sources"]}
        self.assertEqual(source_states["active-one"], "ok")
        self.assertEqual(source_states["active-two"], "ok")
        self.assertEqual(source_states["unknown-one"], "skipped_inactive")

    def test_unscoped_legacy_catalog_is_skipped_until_refreshed(self) -> None:
        calls: list[str] = []

        def fake_fetch(url: str, **_kwargs) -> SimpleNamespace:
            calls.append(url)
            return SimpleNamespace(url=url, body=fixture("leak-table-page-1.html"), status_code=200)

        result = scrape_victims.crawl_catalog(
            {"groups": [{
                "group_id": "legacy", "name": "Legacy", "status": "active",
                "profile_url": "https://www.watchguard.com/legacy",
                "leak_sites": [{"url": "https://unscoped.example.invalid/"}],
            }]},
            fetcher=fake_fetch,
        )
        self.assertEqual(calls, [])
        self.assertEqual(result["sources"][0]["status"], "skipped_unscoped_catalog")
        self.assertEqual(result["groups"][0]["source_issue"], "catalog_missing_extortion_scope")

    def test_crawl_continues_after_source_errors_and_marks_first_page_absence_unknown(self) -> None:
        previous = {
            "sources": [],
            "sightings": [{
                "id": "historical", "group_id": "group-a", "source_id": scrape_victims.source_id_for("https://good.example.invalid/", "group-a"),
                "organization": "Old Victim", "listing_state": "listed", "first_seen_at": "2026-09-01T00:00:00Z", "last_seen_at": "2026-09-01T00:00:00Z",
            }],
        }
        calls: list[str] = []

        def fake_fetch(url: str, **_kwargs) -> SimpleNamespace:
            calls.append(url)
            if "bad.example" in url:
                raise FetchError("http_503", http_status=503)
            return SimpleNamespace(url=url, body=fixture("leak-table-page-1.html"), status_code=200)

        catalog = {"groups": [{
            "group_id": "group-a", "name": "Group A", "status": "active", "leak_sites_scope": "extortion_links", "profile_url": "https://www.watchguard.com/a",
            "leak_sites": [{"url": "https://bad.example.invalid/"}, {"url": "https://good.example.invalid/"}],
        }]}
        result = scrape_victims.crawl_catalog(
            catalog,
            previous,
            fetcher=fake_fetch,
            budget_seconds=10,
            request_delay_seconds=0,
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual({item["status"] for item in result["sources"]}, {"offline", "ok"})
        old = next(item for item in result["sightings"] if item["id"] == "historical")
        self.assertEqual(old["listing_state"], "unknown")

    def test_budget_skips_queued_sources_and_preserves_sightings_as_unknown(self) -> None:
        source_url = "https://budget.example.invalid/"
        source_id = scrape_victims.source_id_for(source_url, "group-a")
        previous = {"sources": [], "sightings": [{
            "id": "historical", "group_id": "group-a", "source_id": source_id,
            "organization": "Old Victim", "listing_state": "listed",
        }]}
        calls: list[str] = []

        def fake_fetch(url: str, **_kwargs) -> SimpleNamespace:
            calls.append(url)
            return SimpleNamespace(url=url, body=fixture("leak-table-page-1.html"), status_code=200)

        result = scrape_victims.crawl_catalog(
            {"groups": [{
                "group_id": "group-a", "name": "Group A", "status": "active", "leak_sites_scope": "extortion_links", "profile_url": "https://www.watchguard.com/a",
                "leak_sites": [{"url": source_url}],
            }]},
            previous,
            fetcher=fake_fetch,
            budget_seconds=0,
        )
        self.assertEqual(calls, [])
        self.assertTrue(result["crawl_partial"])
        self.assertEqual(result["sources"][0]["status"], "skipped_budget")
        self.assertEqual(result["sightings"][0]["listing_state"], "unknown")

    def test_budget_drains_in_flight_request_before_saving_partial_results(self) -> None:
        def fake_fetch(url: str, **_kwargs) -> SimpleNamespace:
            time.sleep(0.04)
            return SimpleNamespace(url=url, body=fixture("leak-table-page-1.html"), status_code=200)

        catalog = {"groups": [{
            "group_id": "group-a", "name": "Group A", "status": "active", "leak_sites_scope": "extortion_links", "profile_url": "https://www.watchguard.com/a",
            "leak_sites": [
                {"url": "https://first.example.invalid/"},
                {"url": "https://second.example.invalid/"},
            ],
        }]}
        result = scrape_victims.crawl_catalog(
            catalog,
            fetcher=fake_fetch,
            budget_seconds=0.02,
            request_delay_seconds=0,
            max_concurrency=1,
        )
        self.assertTrue(result["crawl_partial"])
        self.assertEqual({item["status"] for item in result["sources"]}, {"ok", "skipped_budget"})
        self.assertTrue(any(item["listing_state"] == "listed" for item in result["sightings"]))

    def test_concurrency_is_capped_at_three(self) -> None:
        lock = threading.Lock()
        active = 0
        max_active = 0

        def fake_fetch(url: str, **_kwargs) -> SimpleNamespace:
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return SimpleNamespace(url=url, body=fixture("leak-table-page-1.html"), status_code=200)

        catalog = {"groups": [{
            "group_id": "group-a", "name": "Group A", "status": "active", "leak_sites_scope": "extortion_links", "profile_url": "https://www.watchguard.com/a",
            "leak_sites": [{"url": f"https://host{index}.example.invalid/"} for index in range(7)],
        }]}
        scrape_victims.crawl_catalog(
            catalog,
            fetcher=fake_fetch,
            budget_seconds=5,
            request_delay_seconds=0,
            max_concurrency=8,
        )
        self.assertLessEqual(max_active, 3)


class StaticSiteTests(unittest.TestCase):
    def test_data_and_assets_use_project_relative_paths(self) -> None:
        html = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
        javascript = (ROOT / "site" / "app.js").read_text(encoding="utf-8")
        self.assertIn('href="./styles.css"', html)
        self.assertIn('src="./app.js"', html)
        self.assertIn('const DATA_URL = "./data/victims.json";', javascript)
        self.assertIn('"skipped_budget"', javascript)
        self.assertIn('"skipped_inactive"', javascript)
        self.assertIn('"skipped_unscoped_catalog"', javascript)
        self.assertIn("dataset.crawl_partial", javascript)


if __name__ == "__main__":
    unittest.main()
