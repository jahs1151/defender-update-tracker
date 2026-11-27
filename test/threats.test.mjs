// Threat names, detection alerts and vendor coverage. Most of these tests are about NOT matching.
import { test } from "node:test";
import assert from "node:assert/strict";
import { threatNamesIn, familyOf, usableFamily, sameFamily, updateFamilyIndex, detectionAlerts, vendorCoverage, parseEncyclopediaSearch } from "../scripts/lib/threats.mjs";

test("family of a Defender detection name", () => {
  assert.equal(familyOf("Trojan:Win32/ValleyRAT.PAHY!MTB"), "ValleyRAT");
  assert.equal(familyOf("Backdoor:MSIL/XWorm"), "XWorm");
  assert.equal(familyOf("Trojan:Win32/Wacatac.B!ml"), "Wacatac");
});

test("generic and short families are never matched", () => {
  for (const f of ["Wacatac", "Agent", "Phish", "FakeLogin", "Kryptik", "Malgent", "Sabsik", "Gen", "Abc1", "CobaltStrike", "Python"]) assert.equal(usableFamily(f), false, f);
  for (const f of ["ValleyRAT", "XWorm", "TamperedChef", "LummaStealer"]) assert.equal(usableFamily(f), true, f);
});

test("threat names from headlines", () => {
  assert.deepEqual(threatNamesIn("Iran-Aligned Volant Manticore Uses IPFS-Based KuboShell Backdoor in Espionage Campaigns"), ["KuboShell"]);
  assert.deepEqual(threatNamesIn("New XWorm variant spreads through fake invoices"), ["XWorm"]);
  assert.deepEqual(threatNamesIn("Attackers deploy a loader dubbed Ravartar against banks"), ["Ravartar"]);
  assert.ok(threatNamesIn("ValleyRAT campaign targets Chinese-speaking users").includes("ValleyRAT"));
});

test("ordinary headlines name no threat", () => {
  for (const t of [
    "Microsoft pushes emergency hotpatch to fix Windows Server crashes",
    "Palo Alto Networks Patches Critical Flaw Used to Root Firewalls",
    "CVE-2026-72965 Windows WebClient Service Elevation of Privilege Vulnerability",
    "CrowdStrike Named a Leader in the 2026 Gartner Magic Quadrant",
    "Hackers Exploit Two GeoServer Flaws as Researchers Warn of RCE Chains",
    "13 Malicious NuGet Packages Target .NET Developers With Fake Job Assessments",
    "North Korean hackers target developers with new malware",
    "The Ransomware Threat Landscape in October",
  ]) assert.deepEqual(threatNamesIn(t), [], t);
});

test("same family: exact compact match, with an optional RAT suffix", () => {
  assert.ok(sameFamily("ValleyRAT", "ValleyRAT"));
  assert.ok(sameFamily("Valley RAT", "ValleyRAT"));
  assert.ok(sameFamily("XWorm", "Xworm"));
  assert.ok(!sameFamily("Lumma", "LummaStealer"));
  assert.ok(!sameFamily("Remcos", "RemcosLoader"));
  assert.ok(!sameFamily("Worm", "XWorm"));
});

const builds = [
  {
    version: "1.463.497.0",
    releasedAt: "2026-11-27T15:52:53.000Z",
    rows: [
      { name: "Trojan:MSIL/XWorm.D!MTB", change: "added", severity: "severe", url: "https://www.microsoft.com/x" },
      { name: "Trojan:Win32/Wacatac.B!ml", change: "added", severity: "severe" },
      { name: "Backdoor:Win64/KuboShell.A", change: "updated", severity: "severe" },
    ],
  },
  { version: "1.463.495.0", releasedAt: "2026-11-27T09:00:00.000Z", rows: [{ name: "Backdoor:Win64/KuboShell.A", change: "added", severity: "severe" }] },
];
const now = new Date("2026-11-27T18:00:00Z");

test("detection alerts: a new detection for a threat named in a recent story", () => {
  const stories = [
    { title: "New XWorm variant spreads through fake invoices", url: "https://news/1", source: "BleepingComputer", published: "2026-11-26T00:00:00Z" },
    { title: "Iran-Aligned Volant Manticore Uses IPFS-Based KuboShell Backdoor", url: "https://news/2", source: "The Hacker News", published: "2026-11-25T00:00:00Z" },
    { title: "Wacatac malware seen everywhere", url: "https://news/3", source: "X", published: "2026-11-26T00:00:00Z" },
    { title: "Old XWorm story", url: "https://news/4", source: "Y", published: "2026-09-01T00:00:00Z" },
  ];
  const alerts = detectionAlerts(builds, stories, { now });
  assert.deepEqual(alerts.map((a) => [a.version, a.detection, a.story.url]), [
    ["1.463.497.0", "Trojan:MSIL/XWorm.D!MTB", "https://news/1"],
    ["1.463.495.0", "Backdoor:Win64/KuboShell.A", "https://news/2"],
  ]);
  assert.deepEqual(detectionAlerts(builds, [stories[3]], { now }), [], "stories older than 14 days do not count");
});

test("family index keeps the first build a family appeared in and drops old ones", () => {
  const idx = updateFamilyIndex({}, builds, 90, now);
  assert.equal(idx.kuboshell.first, "1.463.495.0");
  assert.equal(idx.kuboshell.last, "1.463.497.0");
  assert.ok(!idx.wacatac, "generic families are not indexed");
  const later = updateFamilyIndex(idx, [], 90, new Date("2027-06-01T00:00:00Z"));
  assert.deepEqual(later, {});
});

test("vendor coverage: Yes from the index, No only on an explicit empty lookup, else Unclear", () => {
  const idx = updateFamilyIndex({}, builds, 90, now);
  const posts = [
    { title: "KuboShell backdoor analysis", url: "https://v/1", source: "Unit 42", published: "2026-11-25T00:00:00Z" },
    { title: "Inside the GlassWorm2 loader", url: "https://v/2", source: "Sophos", published: "2026-11-25T00:00:00Z" },
    { title: "Inside the ShadowPadX implant", url: "https://v/3", source: "ESET", published: "2026-11-25T00:00:00Z" },
    { title: "Our 2026 predictions", url: "https://v/4", source: "CrowdStrike", published: "2026-11-25T00:00:00Z" },
  ];
  const lookups = { glassworm2: { names: [], answered: true, empty: true } };
  const rows = vendorCoverage(posts, idx, lookups);
  assert.deepEqual(rows.map((r) => [r.threat, r.coverage]), [
    ["KuboShell", "Yes"],
    ["GlassWorm2", "No"],
    ["ShadowPadX", "Unclear"],
  ]);
  assert.deepEqual(rows[0].detections, ["Backdoor:Win64/KuboShell.A"]);
});

test("encyclopedia search parsing keeps only the searched family", () => {
  const html = `<div>Results for: ValleyRAT</div><div>3 entries found</div><a>Trojan:Win32/ValleyRAT.A!MTB</a><a>Trojan:Win32/Valleyx.B</a><a>Backdoor:Win32/ValleyRAT.PAHY!MTB</a>`;
  const r = parseEncyclopediaSearch(html, "ValleyRAT");
  assert.deepEqual(r.names, ["Trojan:Win32/ValleyRAT.A!MTB", "Backdoor:Win32/ValleyRAT.PAHY!MTB"]);
  assert.equal(r.answered, true);
  assert.equal(r.empty, false);
  const none = parseEncyclopediaSearch("<p>No results found for: GlassWorm2</p><p>0 entries found</p>", "GlassWorm2");
  assert.deepEqual([none.answered, none.empty], [true, true]);
  const broken = parseEncyclopediaSearch("<p>Loading…</p>", "GlassWorm2");
  assert.equal(broken.answered, false, "a page that did not render results is not a No");
  // Live page, Nov 2026: the ?query= URL masks the term and reports 0 even for a family Defender detects.
  const masked = parseEncyclopediaSearch("<p>No results found for: *** 0 entries found.</p>", "ValleyRAT");
  assert.deepEqual([masked.answered, masked.empty], [false, false]);
});

test("notable new detections: families first seen in each build, Windows only", async () => {
  const { firstSeenByBuild } = await import("../scripts/lib/threats.mjs");
  const bs = [
    { version: "1.463.497.0", releasedAt: "2026-11-27T15:52:53.000Z", rows: [
      { name: "Trojan:Win64/KuboShell.B", change: "added" },
      { name: "Trojan:Win64/SteelC.PAHY!MTB", change: "added" },
      { name: "Trojan:AndroidOS/Joker.A", change: "added" },
      { name: "Trojan:Win32/Wacatac.B!ml", change: "added" },
    ] },
    { version: "1.463.495.0", releasedAt: "2026-11-27T09:00:00.000Z", rows: [{ name: "Backdoor:Win64/KuboShell.A", change: "added" }] },
  ];
  const idx = updateFamilyIndex({}, bs, 90, now);
  assert.deepEqual(firstSeenByBuild(bs, idx), { "1.463.497.0": ["Trojan:Win64/SteelC.PAHY!MTB"], "1.463.495.0": ["Backdoor:Win64/KuboShell.A"] });
});
