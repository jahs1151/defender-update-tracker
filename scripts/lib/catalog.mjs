// Microsoft's threat catalog (the WDSI threat encyclopedia search), saved as a static index so the site can
// search it in the browser. Microsoft's search page sends no CORS headers, so a browser on GitHub Pages cannot
// ask it directly; the scheduled job asks instead and publishes site/data/catalog/*.json.
//
// How the search behaves (checked Nov 2026): a query is matched against the start of the full name
// ("Trojan:Win32/Bear" lists names starting with that), results come 20 a page (&page=N), and a query that
// matches more than about 500 names is cut off at about 500. So the catalog is walked as a prefix tree:
// when a prefix reports 480 or more names it is split by the next character, otherwise every page is read.
// Windows only: names for other platforms are never queried or stored (see platform.mjs).
import { isWindowsDetection } from "./platform.mjs";

import { SEARCH_URL, ENTRY_URL } from "../../site/assets/catalog.js";
export { SEARCH_URL, ENTRY_URL };
/** A query reporting this many names or more may have been cut off, so it is split further. */
export const CUT_OFF = 480;

/** Detection types (the part before the colon) that the catalog is walked under. */
export const TYPES = [
  "Adware", "Backdoor", "Behavior", "BrowserModifier", "Constructor", "DDoS", "Dialer", "Exploit", "Flooder", "HackTool", "Joke", "Misleading",
  "Monitor", "MonitoringTool", "PUA", "Phish", "Program", "PWS", "RemoteAccess", "Ransom", "Rogue", "Rootkit", "SettingsModifier", "SoftwareBundler",
  "Spammer", "Spoofer", "Spyware", "TrojanClicker", "TrojanDownloader", "TrojanDropper", "TrojanNotifier", "TrojanProxy", "TrojanSpy", "Trojan",
  "Tool", "VirTool", "Virus", "Worm", "Wiper", "Stealer", "Coinminer", "Downloader", "Exploit", "Packed", "Suspicious", "Malware", "Win32", "Unwanted",
];
/** Windows platforms (the part between the colon and the slash). */
export const PLATFORMS = [
  "Win32", "Win64", "MSIL", "WinNT", "Win16", "DOS", "JS", "VBS", "VBA", "PowerShell", "BAT", "HTML", "O97M", "W97M", "X97M", "Script", "INF", "LNK",
  "HTA", "ASP", "Python", "AutoIt", "ALisp", "Java", "PDF", "SWF", "XML", "NPM", "PyPI", "WinREG", "WinHlp", "MSOffice", "MSWord", "MSExcel", "Win95", "Win98",
];

const decode = (s = "") => s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").trim();

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
/** "Apr 24, 2024" -> "2024-04-24". "" when it cannot be read. */
export function isoDate(text = "") {
  const m = /([A-Za-z]{3})[a-z]*\.?\s+(\d{1,2}),?\s+(\d{4})/.exec(text);
  if (!m || !(m[1].toLowerCase() in MONTHS)) return "";
  return new Date(Date.UTC(Number(m[3]), MONTHS[m[1].toLowerCase()], Number(m[2]))).toISOString().slice(0, 10);
}

const SEVERITY = { severe: "s", high: "h", moderate: "m", low: "l" };
export const SEVERITY_NAME = { s: "severe", h: "high", m: "moderate", l: "low", "": "" };

/** One search result page -> { total, rows: [{ name, severity: "s"|"h"|"m"|"l"|"", updated: "YYYY-MM-DD" }] }. */
export function parseCatalogPage(html = "") {
  const total = Number((/id="totalCount">\s*([\d,]+)\s*</.exec(html)?.[1] || "0").replace(/,/g, ""));
  const rows = [];
  const parts = String(html).split('id="threatLink"').slice(1);
  for (const part of parts) {
    const block = part.split("</section>")[0];
    const name = decode(/<a[^>]*href="[^"]*"[^>]*>([^<]*)<\/a>/.exec(block)?.[1] || "");
    if (!name) continue;
    const date = /id="threatPubDate">\s*Updated on\s*([^<]*)</i.exec(block)?.[1] || "";
    const sev = (/id="threatLevel"[\s\S]*?name="([a-z]+)"/i.exec(block)?.[1] || "").toLowerCase();
    rows.push({ name, severity: SEVERITY[sev] || "", updated: isoDate(date) });
  }
  return { total, rows };
}

export { shardOf, shardForQuery } from "../../site/assets/catalog.js";

const CHILD_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789._!-$@#";

/** The queries that split a cut-off prefix. */
export const children = (prefix) => [...CHILD_CHARS].map((c) => prefix + c);

/**
 * Read every page of one query. fetchPage(query, page) -> html. Returns { total, rows, cut } where cut means
 * the query is at the cut-off and must be split.
 */
export async function readQuery(query, fetchPage, { maxPages = 30 } = {}) {
  const first = parseCatalogPage(await fetchPage(query, 1));
  const prefix = query.toLowerCase();
  const keep = (rows) => rows.filter((r) => r.name.toLowerCase().startsWith(prefix) && isWindowsDetection(r.name));
  const rows = [...keep(first.rows)];
  if (first.total >= CUT_OFF) return { total: first.total, rows, cut: true };
  for (let page = 2; page <= maxPages && first.rows.length && rows.length < first.total; page += 1) {
    const next = parseCatalogPage(await fetchPage(query, page));
    if (!next.rows.length) break;
    rows.push(...keep(next.rows));
    if (next.rows.length < 20) break;
  }
  return { total: first.total, rows, cut: false };
}

/** Compact row for the shard files: [name, severity, updated]. */
export const toRow = (r) => [r.name, r.severity || "", r.updated || ""];
