// Search over the static copy of Microsoft's threat catalog (data/catalog/<shard>.json), shared by the browser
// page and the Node tests. Pure functions. See scripts/lib/catalog.mjs for how the index is built.

export const SEARCH_URL = "https://www.microsoft.com/en-us/wdsi/threats/threat-search";
export const ENTRY_URL = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=";
export const SEVERITY_NAME = { s: "severe", h: "high", m: "moderate", l: "low", "": "" };

const compact = (s = "") => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "");

/** Which shard file holds a name: the first letter or digit of its family part ("Trojan:Win32/Bearfoos" -> "b"). */
export function shardOf(name = "") {
  const c = String(name).replace(/^[^/]*\//, "").charAt(0).toLowerCase();
  return /[a-z0-9]/.test(c) ? c : "_";
}

/** The shard to load for a typed query: the part after "/" when there is one, else the first character. */
export function shardForQuery(query = "") {
  const q = String(query).trim();
  const c = (q.includes("/") ? q.slice(q.indexOf("/") + 1) : q).trim().charAt(0).toLowerCase();
  return /[a-z0-9]/.test(c) ? c : "_";
}

export const catalogSearchUrl = (query) => `${SEARCH_URL}?query=${encodeURIComponent(String(query).trim())}`;
export const entryUrl = (name) => `${ENTRY_URL}${encodeURIComponent(name).replace(/%3A/gi, ":").replace(/%2F/gi, "/")}`;

/** "2024-04-24" -> "Apr 24, 2024". */
export function longDate(iso = "") {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (!m) return "";
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
}

/**
 * Catalog rows ([name, severity, updated]) containing the query, ignoring case, spaces and punctuation.
 * Best first: the exact name, then names whose family starts with the text, then the rest, newest update first.
 * Returns { total, rows: [{ name, severity, updated }] } (rows capped at limit).
 */
export function searchCatalog(rows = [], query = "", { limit = 50, minLength = 3 } = {}) {
  const q = compact(query);
  if (q.length < minLength) return { total: 0, rows: [], tooShort: true };
  const hits = [];
  for (const [name, severity = "", updated = ""] of rows) {
    const c = compact(name);
    if (!c.includes(q)) continue;
    const family = compact(name.replace(/^[^/]*\//, ""));
    hits.push({ name, severity: SEVERITY_NAME[severity] ?? severity, updated, rank: c === q ? 0 : family.startsWith(q) || c.startsWith(q) ? 1 : 2 });
  }
  hits.sort((a, b) => a.rank - b.rank || (b.updated || "").localeCompare(a.updated || "") || a.name.localeCompare(b.name));
  return { total: hits.length, rows: hits.slice(0, limit).map(({ rank: _r, ...r }) => r), tooShort: false };
}
