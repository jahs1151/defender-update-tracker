#!/usr/bin/env node
// Fetch every public source once and write site/data/pulse.json.
// Run by .github/workflows/refresh-and-deploy.yml. Node 20+, no npm packages.
//
// A section that fails keeps its last good data, marked stale, so the page is never empty.
import { readFile, writeFile, appendFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as S from "./lib/sources.mjs";
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
};

async function main() {
  const started = Date.now();
  const now = new Date();
  const previous = await readPrevious();
  const checkedAt = now.toISOString();

  const packages = await S.loadPackages();
  const [intelligence, productUpdates, changelog, sense, patchTuesday, kev, knownIssues, intune, mde, news] = await Promise.all([
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
  ]);

  // The changelog uses the same unlabeled clock as the definitions page.
  if (changelog.ok && changelog.data.releasedRaw) {
    const zone = intelligence.data?.clockZone || previous?.sections?.intelligence?.data?.clockZone || "UTC";
    const at = parseUsClock(changelog.data.releasedRaw, zone);
    changelog.data.releasedAt = at ? at.toISOString() : "";
  }

  const fresh = { packages, intelligence, productUpdates, changelog, sense, patchTuesday, kev, knownIssues, intune, mde, news };
  const sections = {};
  for (const [key, result] of Object.entries(fresh)) {
    const prev = previous?.sections?.[key];
    if (result.ok) {
      sections[key] = { label: LABELS[key], ok: true, stale: false, checkedAt, lastOkAt: checkedAt, detail: result.detail, data: result.data };
    } else if (prev?.data) {
      sections[key] = { ...prev, label: LABELS[key], ok: false, stale: true, checkedAt, detail: `${result.detail}. Showing data from the last good check.` };
    } else {
      sections[key] = { label: LABELS[key], ok: false, stale: false, checkedAt, lastOkAt: "", detail: result.detail, data: null };
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

  await writeFile(OUT, `${JSON.stringify(pulse, null, 1)}\n`);
  const okCount = Object.values(sections).filter((s) => s.ok).length;
  console.log(`pulse.json written in ${((Date.now() - started) / 1000).toFixed(1)} s · ${okCount}/${Object.keys(sections).length} sources ok · content ${changed ? "changed" : "unchanged"}`);
  for (const [key, s] of Object.entries(sections)) console.log(`  ${s.ok ? "ok  " : s.stale ? "old " : "FAIL"} ${key}: ${s.detail}`);
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `changed=${changed}\n`);
  if (okCount === 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
