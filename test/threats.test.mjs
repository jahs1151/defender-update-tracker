// Threat names, detection alerts and vendor coverage. Most of these tests are about NOT matching.
import { test } from "node:test";
import assert from "node:assert/strict";
import { threatNamesIn, familyOf, usableFamily, sameFamily, updateFamilyIndex, detectionAlerts, updateDetectionIndex, relatedFamily, detectionsFor, parseEncyclopediaResults, coverageRows, kevRows } from "../scripts/lib/threats.mjs";

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

// ---------- 30-day index, encyclopedia, coverage and KEV rows ----------
const vinciBuild = { version: "1.463.467.0", releasedAt: "2026-11-25T15:45:22.000Z", rows: [{ name: "Backdoor:PowerShell/VinciRAT!MSR", change: "added" }, { name: "Trojan:Win32/Wacatac.B!ml", change: "added" }] };

test("detection index keeps every version for 30 days and finds older detections", () => {
  const idx = updateDetectionIndex({}, [vinciBuild, ...builds], 30, now);
  assert.deepEqual(Object.keys(idx).sort(), ["1.463.467.0", "1.463.495.0", "1.463.497.0"]);
  assert.deepEqual(detectionsFor(idx, "VinciRAT").map((d) => d.name), ["Backdoor:PowerShell/VinciRAT!MSR"]);
  assert.deepEqual(detectionsFor(idx, "vincirat").map((d) => d.version), ["1.463.467.0"], "case does not matter");
  assert.deepEqual(detectionsFor(idx, "Wacatac"), [], "generic families never match");
  const later = updateDetectionIndex(idx, [], 30, new Date("2026-12-26T00:00:00Z"));
  assert.ok(!later["1.463.467.0"], "dropped after 30 days");
  assert.ok(later["1.463.497.0"]);
});

test("partial matching: a name that begins the other, never a word inside it", () => {
  assert.ok(relatedFamily("Remus", "RemusStealer"));
  assert.ok(relatedFamily("LummaStealer", "Lumma"));
  assert.ok(relatedFamily("valleyrat", "ValleyRAT"));
  assert.ok(!relatedFamily("Worm", "XWorm"));
  assert.ok(!relatedFamily("Stealer", "RemusStealer"));
  assert.ok(!relatedFamily("Agent", "AgentTesla"), "a generic name never matches");
  assert.ok(!relatedFamily("Antino", "AntiNOD"), "live false match, Nov 2026: the rest must be a malware-type word");
  assert.ok(!relatedFamily("ARTEX", "ARTEXNetworkStages"));
  assert.ok(!relatedFamily("ValleyRAT", "Valleyx"));
});

test("encyclopedia results: the live page's count line and names", () => {
  const html = `<p>No results found for: *** 57 entries found. Displaying page 1 of 3.</p>
    <h2 id="threatLink"><a href="malware-encyclopedia-description?Name=Trojan:Win32/ValleyRAT!MSR">Trojan:Win32/ValleyRAT!MSR</a></h2>
    <h2><a>Trojan:Win32/Valleyx.B</a></h2><h2><a>Backdoor:Win64/ValleyRAT!MTB</a></h2>`;
  const r = parseEncyclopediaResults(html, "ValleyRAT");
  assert.deepEqual([r.answered, r.count], [true, 57]);
  assert.deepEqual(r.names, ["Trojan:Win32/ValleyRAT!MSR", "Backdoor:Win64/ValleyRAT!MTB"]);
  const none = parseEncyclopediaResults("<p>No results found for: *** 0 entries found.</p>", "GlassWorm2");
  assert.deepEqual([none.answered, none.count, none.names], [true, 0, []]);
  assert.equal(parseEncyclopediaResults("<p>Loading…</p>", "GlassWorm2").answered, false, "no count line is not an answer");
});

test("coverage rows: Yes from the index or encyclopedia, Unclear only on an answer, else Lookup failed", () => {
  const idx = updateDetectionIndex({}, [vinciBuild, ...builds], 30, now);
  const items = [
    { title: "VinciRAT spreads through PowerShell", url: "https://v/1", source: "eSentire", published: "2026-11-26T00:00:00Z", names: ["VinciRAT"] },
    { title: "Inside the ShadowPadX implant", url: "https://v/2", source: "ESET", published: "2026-11-25T00:00:00Z", names: ["ShadowPadX"] },
    { title: "Inside the GlassWorm2 loader", url: "https://v/3", source: "Sophos", published: "2026-11-25T00:00:00Z", names: ["GlassWorm2"] },
    { title: "New XWormZ variant", url: "https://n/1", source: "BleepingComputer", kind: "news", published: "2026-11-25T00:00:00Z", names: ["XWormZ"] },
    { title: "Our 2026 predictions", url: "https://v/4", source: "CrowdStrike", published: "2026-11-25T00:00:00Z", names: [] },
  ];
  const lookups = {
    glassworm2: { answered: true, names: [], checkedAt: "2026-11-27T10:00:00.000Z" },
    shadowpadx: { answered: false, names: [], error: "HTTP 403", checkedAt: "2026-11-27T10:00:00.000Z" },
    xwormz: { answered: true, names: ["Trojan:Win32/XWormZ!MTB"], checkedAt: "2026-11-27T09:00:00.000Z" },
  };
  const rows = coverageRows(items, idx, lookups, now);
  assert.deepEqual(rows.map((r) => [r.threat, r.coverage]), [
    ["VinciRAT", "Yes"],
    ["ShadowPadX", "Lookup failed, retrying"],
    ["GlassWorm2", "Unclear"],
    ["XWormZ", "Yes"],
  ]);
  assert.match(rows[0].basis, /1\.463\.467\.0/);
  assert.equal(rows[3].kind, "news");
  assert.equal(rows[2].checkedAt, "2026-11-27T10:00:00.000Z", "each row carries its own check time");
  assert.equal(rows[0].checkedAt, now.toISOString());
});

test("KEV rows: last 14 days, due date, and a detection only when a name carries the CVE", () => {
  const idx = updateDetectionIndex({}, [{ version: "1.463.490.0", releasedAt: "2026-11-26T00:00:00Z", rows: [{ name: "Exploit:Win32/CVE-2026-1234.A", change: "added" }] }], 30, now);
  const recent = [
    { cve: "CVE-2026-1234", vendor: "Microsoft", product: "Windows", name: "Windows EoP", dateAdded: "2026-11-25", dueDate: "2026-12-16" },
    { cve: "CVE-2026-9999", vendor: "Ivanti", product: "EPMM", name: "Ivanti RCE", dateAdded: "2026-11-20", dueDate: "2026-12-11" },
    { cve: "CVE-2026-1111", vendor: "Cisco", product: "IOS", name: "Old", dateAdded: "2026-10-01", dueDate: "2026-10-22" },
  ];
  const rows = kevRows(recent, idx, {}, { now });
  assert.deepEqual(rows.map((r) => [r.cve, r.dueDate, r.coverage]), [
    ["CVE-2026-1234", "2026-12-16", "Detection found"],
    ["CVE-2026-9999", "2026-12-11", "No public MDE detection found"],
  ]);
  assert.deepEqual(rows[0].detections, ["Exploit:Win32/CVE-2026-1234.A"]);
});

test("encyclopedia lookup: prefixed queries, retries next run on failure, 24-hour cache", async () => {
  const { lookupEncyclopedia } = await import("../scripts/lib/sources.mjs");
  const asked = [];
  const page = (q) => (/ValleyRAT/.test(q) ? `<p>1 entries found</p><a>Trojan:Win32/ValleyRAT!MTB</a>` : `<p>No results found for: *** 0 entries found.</p>`);
  const get = async (url) => {
    const q = decodeURIComponent(url.split("query=")[1]);
    asked.push(q);
    if (/Broken/.test(q)) throw new Error("HTTP 403");
    return page(q);
  };
  const out = await lookupEncyclopedia(["ValleyRAT", "GlassWorm2", "BrokenOne"], {}, { now, get, pause: 0 });
  assert.equal(asked[0], "ValleyRAT!MTB", "never a bare name: Microsoft masks those");
  assert.ok(asked.every((q) => /[:!/]/.test(q)));
  assert.deepEqual(out.valleyrat.names, ["Trojan:Win32/ValleyRAT!MTB"]);
  assert.deepEqual([out.glassworm2.answered, out.glassworm2.names], [true, []]);
  assert.deepEqual([out.brokenone.answered, out.brokenone.error], [false, "HTTP 403"]);
  asked.length = 0;
  const again = await lookupEncyclopedia(["ValleyRAT", "GlassWorm2", "BrokenOne"], out, { now: new Date(now.getTime() + 3600000), get, pause: 0 });
  assert.ok(asked.every((q) => /BrokenOne/.test(q)), "answers are cached for 24 hours; only the failure is asked again");
  assert.equal(again.valleyrat.checkedAt, out.valleyrat.checkedAt);
  asked.length = 0;
  await lookupEncyclopedia(["ValleyRAT"], out, { now: new Date(now.getTime() + 25 * 3600000), get, pause: 0 });
  assert.ok(asked.length > 0, "asked again after 24 hours");
});
