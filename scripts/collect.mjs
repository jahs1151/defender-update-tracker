#!/usr/bin/env node
// Fetch every public source once and write site/data/pulse.json.
// Run by .github/workflows/refresh-and-deploy.yml. Node 20+, no npm packages.
//
// A section that fails keeps its last good data, marked stale, so the page is never empty.
import { readFile, writeFile, appendFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as S from "./lib/sources.mjs";
import { lastModifiedSeen } from "./lib/http.mjs";
import { parseUsClock, patchWindow } from "../site/assets/time.js";
import { diffPulse, contentKey } from "./lib/diff.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(root, "site", "data", "pulse.json");

async function readPrevious() {
  try {
    return JSON.parse(await readFile(OUT, "utf8"));
  } catch {
    return null;
  }
}

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
};

// The page a reader can open for each source, and the URL whose Last-Modified header is shown.
const PAGES = {
  packages: [S.URLS.productUpdates, S.URLS.wimPage],
  intelligence: [S.URLS.definitions, S.URLS.definitions],
  productUpdates: [S.URLS.monthlyReleases, S.URLS.monthlyReleases],
  changelog: [S.URLS.changelog, S.URLS.changelog],
  sense: [S.URLS.senseCatalog, S.URLS.senseCatalog],
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
  const [intelligence, productUpdates, changelog, sense, patchTuesday, kev, knownIssues, intune, mde, news, community, hashes, roadmap] = await Promise.all([
    S.loadIntelligence(packages.data),
    S.loadProductUpdates(),
    S.loadChangelog(),
    S.loadSense(),
    S.loadPatchTuesday(now),
    S.loadKev(),
    S.loadKnownIssues(),
    S.loadIntune(),
    S.loadMdeWhatsNew(),
    S.loadNews(),
    S.loadCommunity(),
    S.loadPublicHashes(previous?.sections?.hashes?.data),
    S.loadRoadmap(),
  ]);
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
  }

  const fresh = { packages, intelligence, productUpdates, changelog, sense, patchTuesday, kev, knownIssues, intune, mde, news, community, qualys, hashes, roadmap };
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

  const pulse = {
    schema: 1,
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
  const shapeChanged = Boolean(previous) && Object.keys(previous.sections || {}).sort().join() !== Object.keys(sections).sort().join();

  await writeFile(OUT, `${JSON.stringify(pulse, null, 1)}\n`);
  const okCount = Object.values(sections).filter((s) => s.ok).length;
  console.log(`pulse.json written in ${((Date.now() - started) / 1000).toFixed(1)} s · ${okCount}/${Object.keys(sections).length} sources ok · content ${changed ? "changed" : "unchanged"}`);
  for (const [key, s] of Object.entries(sections)) console.log(`  ${s.ok ? "ok  " : s.stale ? "old " : "FAIL"} ${key}: ${s.detail}`);
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `changed=${changed || shapeChanged}\n`);
  if (okCount === 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
