# Ransomwatch

A small public threat-intelligence dashboard that records organization names listed on ransomware group leak sites. WatchGuard's Ransomware Tracker supplies the group catalog and direct leak-site endpoints. GitHub Actions refresh the catalog and collect listing metadata; GitHub Pages serves the static dashboard.

Victim listings are unverified claims published by criminal groups. This project stores names and limited listing metadata only. It does not download, mirror, or link to leaked files, and it does not collect personal contact details.

## Data collected

- site/data/groups.json contains the WatchGuard group name, status, profile URL, first/last-seen metadata, and direct website or Tor leak-site endpoints.
- site/data/victims.json contains historical sightings with organization, group, source-reported date/country/sector when available, first/last observation timestamps, listing state, source host, and WatchGuard profile attribution.

Listing state is listed when a full successful crawl currently shows the organization, not_seen when a complete crawl no longer shows it, and unknown when a source is offline, unsupported, incomplete, or no longer listed by WatchGuard. Historical sightings are retained.

The collectors use conservative HTML table and victim-card parsing. A site's layout may not be recognized; those sources are marked unsupported. Add a parser in scripts/scrape_victims.py when a site needs a specific layout adapter. The crawler follows listing pagination only, uses low request rates, restricts requests to HTTP(S) public hosts or .onion hosts, validates redirect targets, and caps response size.

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
