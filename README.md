# Ransomwatch

A small public threat-intelligence dashboard that records organization names listed on ransomware group leak sites. WatchGuard's Ransomware Tracker supplies the group catalog and direct leak-site endpoints. GitHub Actions refresh the catalog and collect listing metadata; GitHub Pages serves the static dashboard.

Listings are claims published by threat actors. Seeing an organization here does not confirm that a data breach occurred or that data was stolen. This project stores names and limited text metadata only. It does not download, mirror, or link to leaked files, and it does not collect personal contact details.

## Data collected

- site/data/groups.json contains the WatchGuard group name, status, profile URL, first/last-seen metadata, and direct website or Tor leak-site endpoints.
- site/data/victims.json contains historical sightings with a normalized organization name, the original post title, a `victim`, `headline`, or `review` classification, group, source-reported date/country/sector when available, optional short listing details, first/last observation timestamps, listing state, source host, and WatchGuard profile attribution.
- Clear headlines and ambiguous posts remain in the data for inspection but do not appear in victim totals or the default victim list. Country values inferred from a leading flag are labeled as inferred.
- Optional descriptions, claimed data size, file count, deadline, and organization website are collected only when explicitly shown on the listing. Those values are attributed to the threat actor and are not independently verified.

The victim crawler checks only groups with WatchGuard status `active`, and only the first listing page at each direct Extortion Links endpoint. It requires the catalog's `leak_sites_scope` marker, so older catalogs are skipped until the WatchGuard catalog refresh runs. A visible organization is marked `listed`; a historical organization absent from page one remains `unknown` because deeper pages are not checked. Offline, unsupported, inactive, unscoped, removed, and time-budget-skipped sources also leave sightings `unknown`. Historical sightings are retained.

The collectors use conservative HTML table and victim-card parsing. A site's layout may not be recognized; those sources are marked unsupported. Add a parser in scripts/scrape_victims.py when a site needs a specific layout adapter. The crawler deduplicates shared URLs, uses at most three concurrent requests with a 25-second fetch deadline and 90-minute crawl budget, restricts requests to HTTP(S) public hosts or `.onion` hosts, validates redirect targets, and caps response size. Progress and per-source errors are flushed to the Actions log. If the time budget is reached, completed sightings are saved and remaining sources are shown as skipped by the budget in coverage. Classification migration retains existing sighting IDs and observation history.

## GitHub setup

1. Create a public GitHub repository and push this local main branch after GitHub CLI authentication is available.
2. In Settings → Pages, set Build and deployment → Source to GitHub Actions.
3. In Settings → Actions → General, allow the workflows to write repository contents. The workflows scope their token permissions to the data commit and Pages deployment jobs.
4. Run Refresh WatchGuard group catalog from the Actions tab. When it completes, the victim crawl and Pages deployment run automatically.

The group catalog also refreshes daily at 03:00 UTC. The second workflow can be dispatched manually to recrawl the current catalog. The Pages site URL appears in the deployment job summary.

## Local use

Requires Python 3.13 or newer and a public Tor SOCKS proxy at 127.0.0.1:9050 if the catalog contains onion sites.

~~~sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/refresh_groups.py
python scripts/scrape_victims.py
python -m http.server 8000 --directory site
~~~

Then open http://localhost:8000. Run the fixture checks with:

~~~sh
python -m unittest discover -s tests -v
~~~

## Project contents

- .github/workflows/refresh-groups.yml refreshes and commits the group catalog.
- .github/workflows/scrape-victims.yml crawls the catalog, commits sightings, and deploys GitHub Pages.
- scripts/ contains the collectors and bounded network/HTML helpers.
- site/ contains the framework-free dashboard and generated JSON.
- tests/fixtures/ contains small HTML examples used by parser tests.
