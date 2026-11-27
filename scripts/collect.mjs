#!/usr/bin/env node
// Fetch every public source once and write site/data/pulse.json.
// Run by .github/workflows/refresh-and-deploy.yml. Node 20+, no npm packages.
//
// A section that fails keeps its last good data, marked stale, so the page is never empty.
import { readFile, writeFile, appendFile, mkdir, readdir, unlink } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as S from "./lib/sources.mjs";
import { lastModifiedSeen } from "./lib/http.mjs";
import { parseUsClock, patchWindow } from "../site/assets/time.js";
import { diffPulse, contentKey } from "./lib/diff.mjs";
import { mergeSenseReleases, trackSenseIssues, senseSignal } from "./lib/sense.mjs";
import { updateFamilyIndex, detectionAlerts, compact, firstSeenByBuild, updateDetectionIndex, coverageRows, kevRows, detectionsFor } from "./lib/threats.mjs";
import { vtLookup, cleanKey, keyShape } from "./lib/virustotal.mjs";
import * as Parse from "./lib/parsers.mjs";
import { appendHistory, buildFeed } from "./lib/notify.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(root, "site", "data", "pulse.json");
const FAMILIES = join(root, "site", "data", "families.json");
const HISTORY = join(root, "site", "data", "changes.json");
const DETECTIONS = join(root, "site", "data", "detections.json");
const FEED = join(root, "site", "feed.xml");

async function readJson(path, fallback = null) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return fallback;
  }
}
const readPrevious = () => readJson(OUT);

const LABELS = {
  packages: "Download packages (go.microsoft.com)",
  intelligence: "Security intelligence page",
  productUpdates: "Platform and engine release list (Learn)",
  changelog: "Detection changelog",
  sense: "Sense (EDR sensor) build, Update Catalog",
  patchTuesday: "Security Update Guide (MSRC API)",
  kev: "CISA Known Exploited Vulnerabilities",
  knownIssues: "Windows release health",
  intune: "Intune what's new",
  mde: "Defender for Endpoint what's new",
  news: "News feeds",
  community: "Reddit (via Arctic Shift)",
  qualys: "Qualys Patch Tuesday QIDs",
  hashes: "Public hashes (TweetFeed + AlienVault OTX)",
  roadmap: "Microsoft 365 roadmap",
  vendors: "Vendor threat research feeds",
  threats: "Detection alerts and vendor coverage (worked out from the sources above)",
};

// The page a reader can open for each source, and the URL whose Last-Modified header is shown.
const PAGES = {
  packages: [S.URLS.productUpdates, S.URLS.wimPage],
  intelligence: [S.URLS.definitions, S.URLS.definitions],
  productUpdates: [S.URLS.monthlyReleases, S.URLS.monthlyReleases],
  changelog: [S.URLS.changelog, S.URLS.changelog],
  sense: [S.URLS.senseCatalog, S.URLS.senseCatalog],
  vendors: ["https://unit42.paloaltonetworks.com/", ""],
  threats: [S.URLS.encyclopedia, ""],
  patchTuesday: ["https://msrc.microsoft.com/update-guide", ""],
  kev: ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog", S.URLS.kev],
  knownIssues: ["https://learn.microsoft.com/en-us/windows/release-health/", "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2"],
  intune: [S.URLS.intuneWhatsNew, S.URLS.intuneWhatsNew],
  mde: [S.URLS.mdeWhatsNew, S.URLS.mdeWhatsNew],
  news: ["https://www.microsoft.com/en-us/security/blog/", "https://www.microsoft.com/en-us/security/blog/feed/"],
  community: ["https://www.reddit.com/r/DefenderATP/", ""],
  qualys: ["https://threatprotect.qualys.com/", ""],
  hashes: ["https://tweetfeed.live/", "https://api.tweetfeed.live/v1/today/sha256"],
  roadmap: ["https://www.microsoft.com/microsoft-365/roadmap", "https://www.microsoft.com/releasecommunications/api/v1/m365"],
};

function pageInfo(key) {
  const [page, fetched] = PAGES[key] || ["", ""];
  const raw = fetched ? lastModifiedSeen.get(fetched) : "";
  const at = raw ? new Date(raw) : null;
  return { page, lastModified: at && !Number.isNaN(at.getTime()) ? at.toISOString() : "" };
}

async function main() {
  const started = Date.now();
  const now = new Date();
  const previous = await readPrevious();
  const checkedAt = now.toISOString();

  const packages = await S.loadPackages();
  const [intelligence, productUpdates, changelog, sense, patchTuesday, kev, knownIssues, intune, mde, news, community, hashes, roadmap, vendors] = await Promise.all([
    S.loadIntelligence(packages.data),
    S.loadProductUpdates(),
    S.loadChangelog(),
    S.loadSense(),
    S.loadPatchTuesday(now, previous?.sections?.patchTuesday?.data),
    S.loadKev(),
    S.loadKnownIssues(),
    S.loadIntune(),
    S.loadMdeWhatsNew(),
    S.loadNews(),
    S.loadCommunity(),
    S.loadPublicHashes(previous?.sections?.hashes?.data),
    S.loadRoadmap(),
    S.loadVendorResearch(now),
  ]);
  let builds = null;
  const qualys = await S.loadQualys(patchTuesday.data?.month || previous?.sections?.patchTuesday?.data?.month || "", previous?.sections?.qualys?.data);

  // The changelog uses the same unlabeled clock as the definitions page.
  if (changelog.ok) {
    const zone = intelligence.data?.clockZone || previous?.sections?.intelligence?.data?.clockZone || "UTC";
    const conv = (raw) => {
      const at = raw ? parseUsClock(raw, zone) : null;
      return at ? at.toISOString() : "";
    };
    changelog.data.releasedAt = conv(changelog.data.releasedRaw);
    for (const h of changelog.data.history || []) h.releasedAt = conv(h.releasedRaw);
    // Detection names per build, newest first, kept in memory for the alerts and the family index.
    builds = (changelog.data.history || []).map((h) => ({ version: h.version, releasedAt: h.releasedAt, rows: h.rows }));
    // Each build's detections go to their own file, loaded by the page only when that build is picked.
    const dir = join(root, "site", "data", "changelog");
    await mkdir(dir, { recursive: true });
    const keep = new Set();
    for (const h of changelog.data.history || []) {
      const file = `${h.version}.json`;
      keep.add(file);
      await writeFile(join(dir, file), `${JSON.stringify({ version: h.version, releasedRaw: h.releasedRaw, releasedAt: h.releasedAt, rows: h.rows })}\n`);
      h.added = h.rows.filter((r) => r.change === "added").length;
      h.updated = h.rows.filter((r) => r.change === "updated").length;
      h.file = `data/changelog/${file}`;
      delete h.rows;
    }
    for (const f of await readdir(dir)) if (f.endsWith(".json") && !keep.has(f)) await unlink(join(dir, f));
  }

  // Every changelog version of the last 30 days, kept in detections.json and matched against threat names.
  const before = JSON.stringify(await readJson(DETECTIONS, {}));
  const detIndex = await fillDetectionIndex(builds, changelog, intelligence.data?.clockZone || previous?.sections?.intelligence?.data?.clockZone || "UTC", now);
  // VirusTotal answers for the public hashes (needs the VIRUSTOTAL_API_KEY secret).
  const detIndexChanged = before !== JSON.stringify(await readJson(DETECTIONS, {}));
  await addVirusTotal(hashes, previous?.sections?.hashes?.data, now);
  const threats = await deriveThreats({ builds, news, vendors, kev, detIndex, previous: previous?.sections, now });
  // Notable new detections: per build, families seen for the first time in that build.
  if (builds && changelog.ok) {
    const first = firstSeenByBuild(builds, await readJson(FAMILIES, {}));
    for (const h of changelog.data.history || []) h.newFamilies = first[h.version] || [];
  }
  const fresh = { packages, intelligence, productUpdates, changelog, sense, patchTuesday, kev, knownIssues, intune, mde, news, community, qualys, hashes, roadmap, vendors, threats };
  const sections = {};
  for (const [key, result] of Object.entries(fresh)) {
    const prev = previous?.sections?.[key];
    if (result.ok) {
      sections[key] = { label: LABELS[key], ok: true, stale: false, checkedAt, lastOkAt: checkedAt, ...pageInfo(key), detail: result.detail, data: result.data };
    } else if (prev?.data) {
      sections[key] = { ...prev, label: LABELS[key], ok: false, stale: true, checkedAt, page: pageInfo(key).page, detail: `${result.detail}. Showing data from the last good check.` };
    } else {
      sections[key] = { label: LABELS[key], ok: false, stale: false, checkedAt, lastOkAt: "", page: pageInfo(key).page, lastModified: "", detail: result.detail, data: null };
    }
  }

  await finishSense(sections, sense, previous?.sections?.sense?.data, now);

  const pulse = {
    schema: 4,
    checkedAt,
    contentChangedAt: previous?.contentChangedAt || checkedAt,
    changes: previous?.changes || [],
    patch: patchWindow(now),
    sections,
  };

  const changed = !previous || contentKey(previous) !== contentKey(pulse);
  if (changed) {
    pulse.contentChangedAt = checkedAt;
    // No diff against the seed snapshot: its gaps would all show up as "new".
    pulse.changes = previous && !previous.seed ? diffPulse(previous, pulse) : [];
  }

  // A new or removed source must reach the committed snapshot too, so its stale fallback works.
  const shapeChanged = Boolean(previous) && (previous.schema !== pulse.schema || Object.keys(previous.sections || {}).sort().join() !== Object.keys(sections).sort().join());

  await writeFile(OUT, `${JSON.stringify(pulse, null, 1)}\n`);
  // Change history and the RSS feed built from it.
  const history = appendHistory(await readJson(HISTORY, []), pulse);
  await writeFile(HISTORY, `${JSON.stringify(history, null, 1)}\n`);
  await writeFile(FEED, buildFeed(history));
  const okCount = Object.values(sections).filter((s) => s.ok).length;
  console.log(`pulse.json written in ${((Date.now() - started) / 1000).toFixed(1)} s · ${okCount}/${Object.keys(sections).length} sources ok · content ${changed ? "changed" : "unchanged"}`);
  for (const [key, s] of Object.entries(sections)) console.log(`  ${s.ok ? "ok  " : s.stale ? "old " : "FAIL"} ${key}: ${s.detail}`);
  // Lookup caches (encyclopedia, VirusTotal) and the detection index must reach the repository even when
  // nothing on the page changed, or the next run starts them over. Failed lookups do not count.
  const stateChanged = stateKey(previous) !== stateKey(pulse) || detIndexChanged;
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `changed=${changed || shapeChanged}\nstate=${stateChanged}\n`);
  if (okCount === 0) process.exitCode = 1;
}

/** The cached lookups worth keeping between runs. */
function stateKey(pulse) {
  const t = pulse?.sections?.threats?.data?.lookups || {};
  const h = pulse?.sections?.hashes?.data?.rows || [];
  return JSON.stringify([
    Object.entries(t).filter(([, v]) => v.answered).map(([k, v]) => `${k}@${v.checkedAt}`).sort(),
    h.filter((r) => r.vtResult && !r.vtResult.error).map((r) => `${r.hash}@${r.vtResult.checkedAt}`).sort(),
  ]);
}

/** Sense release history, KB text and the tracked issues, built on top of the catalog section. */
async function finishSense(sections, fresh, prev, now) {
  const s = sections.sense;
  if (!s?.data) return;
  const curated = await readJson(join(root, "site", "data", "curated.json"), {});
  const freshKb = fresh.ok ? fresh.data.kb : null;
  // A failed KB read keeps the last good text, marked so no stage is inferred from it.
  const kb = freshKb?.ok ? freshKb : prev?.kb?.version || prev?.kb?.knownIssues ? { ...prev.kb, ok: false, stale: true, error: freshKb?.error || "Not read this run" } : freshKb || prev?.kb || null;
  // On a failed catalog read, the last good catalog rows (or, from an older snapshot, its latest build) still count.
  const fromLatest = (s.data.builds || []).map((b) => ({ version: s.data.latest?.version, date: b.date, channel: b.channel, title: b.os }));
  const catalogRows = fresh.ok ? fresh.data.catalogRows || [] : s.data.catalogRows || (s.data.latest?.version ? fromLatest : []);
  const releases = mergeSenseReleases(prev?.releases || [], catalogRows, freshKb?.ok ? freshKb : null, now.toISOString().slice(0, 10));
  const posts = [
    ...(sections.news?.data?.items || []).map((n) => ({ ...n, where: n.source })),
    ...(sections.community?.data?.posts || []).map((p) => ({ ...p, where: p.community })),
  ];
  const issues = trackSenseIssues(curated.senseIssues || [], prev?.issues || [], {
    kb,
    latest: releases[0]?.version || "",
    posts,
    knownIssues: sections.knownIssues?.data?.rows || [],
    now,
  });
  s.data = { ...s.data, kb, releases, issues, signal: senseSignal(posts, now) };
}

/**
 * Rolling 30-day index of every detection name per changelog version (site/data/detections.json).
 * The changelog page lists far older versions; each run reads up to 30 versions not yet indexed,
 * newest first, and stops at the first one released more than 30 days ago.
 */
async function fillDetectionIndex(builds, changelog, zone, now) {
  const stored = await readJson(DETECTIONS, {});
  let index = updateDetectionIndex(stored.versions || {}, builds || [], 30, now);
  // The newest version already known to be older than 30 days: nothing at or after it in the list is read.
  let before = stored.before || "";
  const versions = changelog.ok ? changelog.data.versions || [] : [];
  const cutoff = new Date(now.getTime() - 30 * 86400000).toISOString();
  let read = 0;
  for (const v of versions) {
    if (v === before || read >= 30) break;
    if (index[v]) continue;
    try {
      read += 1;
      const p = Parse.parseChangelog(await S.getChangelogVersion(v));
      const at = p.releasedRaw ? parseUsClock(p.releasedRaw, zone) : null;
      const releasedAt = at ? at.toISOString() : "";
      if (releasedAt && releasedAt < cutoff) {
        before = v;
        break;
      }
      index = updateDetectionIndex(index, [{ version: p.version || v, releasedAt, rows: p.rows }], 30, now);
    } catch {
      /* the next run tries this version again */
    }
  }
  const body = Object.entries(index).sort(([x], [y]) => y.localeCompare(x, undefined, { numeric: true })).map(([k, e]) => `${JSON.stringify(k)}:${JSON.stringify(e)}`).join(",\n");
  if (changelog.ok || builds) await writeFile(DETECTIONS, `{"before":${JSON.stringify(before)},"versions":{\n${body}\n}}\n`);
  console.log(`  detection index: ${Object.keys(index).length} versions in 30 days, ${read} read this run`);
  return index;
}

/** VirusTotal results for the hash list, carried over from the last run and refreshed after 24 hours. */
async function addVirusTotal(hashes, prevData, now) {
  if (!hashes.ok) return;
  const prevByHash = new Map((prevData?.rows || []).map((r) => [r.hash, r.vtResult]));
  const rows = hashes.data.rows.map((r) => ({ ...r, vtResult: r.vtResult || prevByHash.get(r.hash) }));
  const key = cleanKey(process.env.VIRUSTOTAL_API_KEY || "");
  const res = await vtLookup(rows, { key, budget: prevData?.vtBudget || {}, now });
  const shape = key ? keyShape(key) : "";
  const vt = { no_key: "VirusTotal key not set", rejected: `VirusTotal rejected the key (${res.reason || "no reason given"}${shape ? `; ${shape}` : ""})`, limited: "VirusTotal limit reached; the rest are checked next run", ok: "" }[res.status.replace("-", "_")] || "";
  const analysed = res.rows.filter((r) => r.vtResult?.found !== undefined).length;
  const gaps = res.rows.filter((r) => r.vtResult?.gap).length;
  hashes.data = { ...hashes.data, rows: res.rows, vtStatus: res.status, vtBudget: res.budget, vtNote: vt };
  hashes.detail = `${hashes.detail} · VirusTotal: ${res.status === "no-key" ? vt : `${analysed} of ${res.rows.length} analysed, ${gaps} that other engines detect and Microsoft does not${vt ? ` (${vt})` : ""}`}`;
}

/** Detection alerts and threat coverage, from the changelog, the news, the vendor feeds and CISA KEV. */
async function deriveThreats({ builds, news, vendors, kev, detIndex, previous: prevSections, now }) {
  const previous = prevSections?.threats?.data;
  try {
    const index = await readJson(FAMILIES, {});
    const families = builds ? updateFamilyIndex(index, builds, 90, now) : index;
    if (builds) await writeFile(FAMILIES, `{\n${Object.entries(families).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${JSON.stringify(v)}`).join(",\n")}\n}\n`);
    const posts = vendors.data?.posts || prevSections?.vendors?.data?.posts || [];
    const newsStories = news.data?.threatStories || prevSections?.news?.data?.threatStories || [];
    const stories = [...newsStories, ...posts];
    const since = new Date(now.getTime() - 14 * 86400000).toISOString();
    const fresh = builds ? detectionAlerts(builds, stories, { now }) : [];
    const seen = new Set(fresh.map((a) => `${a.version}|${a.detection}`));
    // The changelog history covers only the last 10 builds, so alerts from earlier runs are kept for 14 days.
    const alerts = [...fresh, ...(previous?.alerts || []).filter((a) => (a.releasedAt || "") >= since && !seen.has(`${a.version}|${a.detection}`))]
      .sort((a, b) => (b.releasedAt || "").localeCompare(a.releasedAt || ""))
      .slice(0, 30)
      .map((a) => ({ ...a, checkedAt: now.toISOString() }));
    // Coverage rows: threats named by vendor research (30 days) and news headlines (14 days).
    const items = [
      ...posts.map((p) => ({ ...p, kind: "vendor" })),
      ...newsStories.filter((s) => (s.published || "") >= since).map((s) => ({ ...s, kind: "news" })),
    ];
    const kevRecent = kev.data?.recent || prevSections?.kev?.data?.recent || [];
    // Only names with no detection in the 30-day index need the encyclopedia.
    const names = [...items.flatMap((p) => p.names || []), ...kevRecent.map((v) => v.cve)].filter((n) => !detectionsFor(detIndex, n).length);
    const lookups = await S.lookupEncyclopedia(names, previous?.lookups || {}, { now });
    // Drop cached answers for names no longer listed, so the cache does not grow forever.
    const wanted = new Set(names.map(compact));
    for (const k of Object.keys(lookups)) if (!wanted.has(k)) delete lookups[k];
    const coverage = coverageRows(items, detIndex, lookups, now);
    const kevCoverage = kevRows(kevRecent, detIndex, lookups, { now });
    const count = (c) => coverage.filter((r) => r.coverage === c).length;
    const indexed = Object.keys(detIndex).length;
    return {
      ok: true,
      detail: `${alerts.length} detection alert${alerts.length === 1 ? "" : "s"} · ${coverage.length} threats: ${count("Yes")} Yes, ${count("Unclear")} Unclear, ${count("Lookup failed, retrying")} lookup failed, ${count("Queued for lookup")} queued · ${kevCoverage.length} KEV CVEs in 14 days · ${indexed} changelog versions indexed (30 days)`,
      data: { alerts, coverage, kev: kevCoverage, lookups, familyCount: Object.keys(families).length, indexedVersions: indexed, indexedNames: Object.values(detIndex).reduce((n, e) => n + e.names.length, 0) },
    };
  } catch (error) {
    return { ok: false, detail: error.message, data: null };
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
