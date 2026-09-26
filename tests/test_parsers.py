from __future__ import annotations

import sys
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

    def test_catalog_walks_all_tracker_pages_and_profiles(self) -> None:
        index_0 = fixture("watchguard-tracker-page-0.html")
        index_1 = fixture("watchguard-tracker-page-1.html")
        profile = fixture("watchguard-profile.html")
        calls: list[str] = []

        def fake_fetch(url: str) -> SimpleNamespace:
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
        self.assertGreaterEqual(len(calls), 5)


class VictimParserTests(unittest.TestCase):
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

    def test_crawl_follows_pages_and_deduplicates_records(self) -> None:
        page_1 = fixture("leak-table-page-1.html")
        page_2 = fixture("leak-table-page-2.html")

        def fake_fetch(url: str) -> SimpleNamespace:
            body = page_2 if "page=2" in url else page_1
            return SimpleNamespace(url=url, body=body)

        result = scrape_victims.crawl_site(
            "https://leak.example.invalid/",
            fetcher=fake_fetch,
            sleep=lambda _delay: None,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["pages_scanned"], 2)
        self.assertEqual({row["organization"] for row in result["records"]}, {"Alpha Research", "Northstar Health"})

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
        self.assertEqual(northstar["listing_state"], "not_seen")

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


class StaticSiteTests(unittest.TestCase):
    def test_data_and_assets_use_project_relative_paths(self) -> None:
        html = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
        javascript = (ROOT / "site" / "app.js").read_text(encoding="utf-8")
        self.assertIn('href="./styles.css"', html)
        self.assertIn('src="./app.js"', html)
        self.assertIn('const DATA_URL = "./data/victims.json";', javascript)


if __name__ == "__main__":
    unittest.main()
