"use strict";

const DATA_URL = "./data/victims.json";

const elements = {
  loading: document.querySelector("#loading-state"),
  error: document.querySelector("#error-state"),
  errorMessage: document.querySelector("#error-message"),
  empty: document.querySelector("#empty-state"),
  emptyTitle: document.querySelector("#empty-title"),
  emptyCopy: document.querySelector("#empty-copy"),
  tableWrap: document.querySelector("#table-wrap"),
  rows: document.querySelector("#victim-rows"),
  search: document.querySelector("#search-input"),
  group: document.querySelector("#group-filter"),
  country: document.querySelector("#country-filter"),
  state: document.querySelector("#state-filter"),
  resultCount: document.querySelector("#result-count"),
  total: document.querySelector("#metric-total"),
  listed: document.querySelector("#metric-listed"),
  groups: document.querySelector("#metric-groups"),
  sources: document.querySelector("#metric-sources"),
  coverageCaption: document.querySelector("#coverage-caption"),
  updated: document.querySelector("#updated-at"),
  coverageSummary: document.querySelector("#coverage-summary"),
  coverageDetails: document.querySelector("#coverage-details"),
};

let dataset = null;

function setText(element, value) {
  element.textContent = value == null || value === "" ? "—" : String(value);
}

function safeProfileUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(value, window.location.href);
    if (url.protocol === "https:" && ["watchguard.com", "www.watchguard.com"].includes(url.hostname)) {
      return url.href;
    }
  } catch (_error) {
    return null;
  }
  return null;
}

function displayDate(value, includeTime = false) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const options = includeTime
    ? { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }
    : { dateStyle: "medium", timeZone: "UTC" };
  return new Intl.DateTimeFormat(undefined, options).format(date);
}

function normalizedState(state) {
  return ["listed", "not_seen", "unknown"].includes(state) ? state : "unknown";
}

function stateLabel(state) {
  return {
    listed: "Currently listed",
    not_seen: "No longer seen",
    unknown: "Unknown / stale",
  }[normalizedState(state)];
}

function sourceCount(status) {
  return (dataset?.sources || []).filter((source) => source.status === status).length;
}

function populateSelect(select, values, firstLabel) {
  select.replaceChildren(new Option(firstLabel, ""));
  for (const value of values) {
    select.add(new Option(value, value));
  }
}

function renderMetrics() {
  const sightings = dataset.sightings || [];
  const listedCount = sightings.filter((item) => normalizedState(item.listing_state) === "listed").length;
  const sourceTotal = (dataset.sources || []).length;
  const sourceOk = sourceCount("ok");
  const skippedInactive = sourceCount("skipped_inactive");
  const skippedRemoved = sourceCount("not_in_catalog");
  const skippedUnscoped = sourceCount("skipped_unscoped_catalog");
  const skippedBudget = sourceCount("skipped_budget");
  const skippedTotal = skippedInactive + skippedRemoved + skippedUnscoped + skippedBudget;
  const checkedTotal = Math.max(0, sourceTotal - skippedTotal);
  const failedTotal = Math.max(0, checkedTotal - sourceOk);
  const profileIssues = (dataset.groups || []).filter((group) => group.source_issue && group.source_issue !== "ok").length;
  const groupCount = (dataset.groups || []).length;
  setText(elements.total, sightings.length.toLocaleString());
  setText(elements.listed, listedCount.toLocaleString());
  setText(elements.groups, groupCount.toLocaleString());
  setText(elements.sources, sourceTotal.toLocaleString());
  setText(elements.coverageCaption, checkedTotal + " checked · " + skippedTotal + " skipped");
  elements.updated.textContent = dataset.updated_at
    ? "Last crawl " + displayDate(dataset.updated_at, true) + " UTC"
    : "No crawl has completed yet";

  const statusCounts = new Map();
  for (const source of dataset.sources || []) {
    const status = source.status || "unknown";
    statusCounts.set(status, (statusCounts.get(status) || 0) + 1);
  }
  elements.coverageSummary.textContent = sourceTotal
    ? sourceOk + " of " + checkedTotal + " checked sources returned a complete first-page listing; " +
      failedTotal + " need attention; " + skippedBudget + " skipped by the time budget; " +
      skippedInactive + " skipped because the group is not active; " + skippedUnscoped +
      " skipped until the catalog is refreshed; " + skippedRemoved + " no longer in the catalog." +
      (profileIssues ? " " + profileIssues + " group profile issue(s) were reported." : "") +
      (dataset.crawl_partial ? " This crawl is partial; skipped sightings remain unknown." : "")
    : "No direct leak-site sources are present in the latest group catalog.";
  elements.coverageDetails.replaceChildren();

  const displayOrder = [
    "ok", "partial", "offline", "unsupported", "skipped_budget", "skipped_inactive",
    "skipped_unscoped_catalog", "not_in_catalog",
  ];
  for (const status of displayOrder) {
    const count = statusCounts.get(status) || 0;
    if (!count) continue;
    const chip = document.createElement("span");
    chip.className = "coverage-chip";
    const number = document.createElement("strong");
    number.textContent = String(count);
    chip.append(number, document.createTextNode(" " + status.replaceAll("_", " ")));
    elements.coverageDetails.append(chip);
  }
}

function populateFilters() {
  const sightings = dataset.sightings || [];
  const groupNames = new Map();
  for (const item of sightings) {
    if (item.group_id && item.group_name) groupNames.set(item.group_id, item.group_name);
  }
  elements.group.replaceChildren(new Option("All groups", ""));
  for (const [groupId, groupName] of [...groupNames.entries()].sort((left, right) => left[1].localeCompare(right[1]))) {
    elements.group.add(new Option(groupName, groupId));
  }
  populateSelect(
    elements.country,
    [...new Set(sightings.map((item) => item.country).filter(Boolean))]
      .sort((left, right) => left.localeCompare(right)),
    "All countries",
  );
}

function searchText(item) {
  return [
    item.organization,
    item.group_name,
    item.country,
    item.sector,
    item.reported_date,
    item.source_host,
  ].filter(Boolean).join(" ").toLocaleLowerCase();
}

function sortTimestamp(item) {
  const reported = Date.parse(item.reported_date || "");
  if (Number.isFinite(reported)) return reported;
  const observed = Date.parse(item.last_seen_at || "");
  return Number.isFinite(observed) ? observed : 0;
}

function makeProfileLink(value) {
  const href = safeProfileUrl(value);
  if (!href) return null;
  const link = document.createElement("a");
  link.className = "profile-link";
  link.href = href;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = "WatchGuard profile ↗";
  return link;
}

function addCell(row, className, text) {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = text || "—";
  row.append(cell);
  return cell;
}

function makeRow(item) {
  const row = document.createElement("tr");
  const organizationCell = addCell(row, "organization-cell", item.organization);
  const profile = makeProfileLink(item.watchguard_profile_url);
  if (profile) organizationCell.append(document.createElement("br"), profile);

  addCell(row, "group-cell", item.group_name);
  addCell(row, "date-cell", item.reported_date || "—");
  addCell(row, "", item.country);
  addCell(row, "", item.sector);
  addCell(row, "date-cell", displayDate(item.last_seen_at));

  const stateCell = document.createElement("td");
  const state = normalizedState(item.listing_state);
  const pill = document.createElement("span");
  pill.className = "state-pill " + state;
  pill.textContent = stateLabel(state);
  stateCell.append(pill);
  row.append(stateCell);
  return row;
}

function filteredSightings() {
  const query = elements.search.value.trim().toLocaleLowerCase();
  const group = elements.group.value;
  const country = elements.country.value;
  const state = elements.state.value;
  return (dataset.sightings || [])
    .filter((item) => !query || searchText(item).includes(query))
    .filter((item) => !group || item.group_id === group)
    .filter((item) => !country || item.country === country)
    .filter((item) => !state || normalizedState(item.listing_state) === state)
    .sort((left, right) => sortTimestamp(right) - sortTimestamp(left));
}

function renderTable() {
  const items = filteredSightings();
  elements.rows.replaceChildren(...items.map(makeRow));
  elements.resultCount.textContent = items.length.toLocaleString() + " shown";
  const hasData = (dataset.sightings || []).length > 0;
  const hasFilters = Boolean(
    elements.search.value || elements.group.value || elements.country.value || elements.state.value,
  );
  elements.tableWrap.hidden = items.length === 0;
  elements.empty.hidden = items.length !== 0;
  if (!items.length) {
    elements.emptyTitle.textContent = hasData && hasFilters ? "No matching sightings" : "No victim sightings yet";
    elements.emptyCopy.textContent = hasData && hasFilters
      ? "Change a filter or clear the search."
      : "The dashboard will populate after a successful leak-site crawl.";
  }
}

async function loadData() {
  try {
    const response = await fetch(DATA_URL, { cache: "no-cache" });
    if (!response.ok) throw new Error("Data request returned " + response.status);
    const result = await response.json();
    if (!result || !Array.isArray(result.sightings) || !Array.isArray(result.sources)) {
      throw new Error("The victim data file has an unexpected format.");
    }
    dataset = result;
    renderMetrics();
    populateFilters();
    elements.loading.hidden = true;
    renderTable();
  } catch (error) {
    elements.loading.hidden = true;
    elements.error.hidden = false;
    elements.errorMessage.textContent = error.message || "Try again later.";
    elements.resultCount.textContent = "";
  }
}

for (const control of [elements.search, elements.group, elements.country, elements.state]) {
  control.addEventListener("input", renderTable);
  control.addEventListener("change", renderTable);
}

loadData();
