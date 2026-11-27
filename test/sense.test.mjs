// Sense release history, KB parsing and the four-stage issue tracker.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as P from "../scripts/lib/parsers.mjs";
import { parseSenseKb, mergeSenseReleases, trackSenseIssues, senseSignal, catalogOs, senseContext, STAGES, KB_URL } from "../scripts/lib/sense.mjs";

const fx = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");
const curated = JSON.parse(readFileSync(new URL("../site/data/curated.json", import.meta.url), "utf8"));

test("KB5005292 page: version, known issues and restart text", () => {
  const kb = parseSenseKb(fx("sense-kb.html"));
  assert.equal(kb.version, "10.8839.26080.2008");
  assert.match(kb.knownIssues, /^Some devices stop reporting telemetry/);
  assert.doesNotMatch(kb.knownIssues, /Restart requirement|script text/);
  assert.equal(kb.restart, "You do not have to restart the device after you apply this update.");
  assert.ok(kb.versions.includes("10.8835.26070.1004"));
});

test("KB page as live in Nov 2026: a minimum version, no known issues, no restart", () => {
  const html = `<p>Version information This package updates the EDR sensor to version 10.8838 or later. For information about what's new</p><h2>Known issues in this update</h2><p>No known issues.</p><h2>Update information</h2><p>This package includes updates and fixes.</p><h2>Restart requirement</h2><p>You don't need to restart the system after you install this update.</p><h2>How to roll back this update</h2><p>Restart the device for the rollback to take effect.</p>`;
  const kb = parseSenseKb(html);
  assert.equal(kb.version, "10.8838 or later");
  assert.equal(kb.knownIssues, "No known issues.");
  assert.equal(kb.restart, "You don't need to restart the system after you install this update.");
  const rel = mergeSenseReleases([], [{ version: "10.8839.26080.2008", date: "2026-11-08", title: "Windows 10/11", channel: "Current Channel (Broad)" }], kb, "2026-11-27");
  assert.deepEqual(rel.map((r) => r.version), ["10.8839.26080.2008"], "a minimum version is not added as a release");
  assert.equal(rel[0].restart, kb.restart);
});

test("KB page with no sections gives empty text, never 'no known issues'", () => {
  const kb = parseSenseKb("<p>Page moved</p>");
  assert.deepEqual([kb.version, kb.knownIssues, kb.restart], ["", "", ""]);
});

test("catalog OS families", () => {
  assert.equal(catalogOs("Windows 10/11 - Update for Microsoft Defender for Endpoint - KB5005292"), "Windows 10 and 11");
  assert.equal(catalogOs("Windows Server 2019+ - Update for ..."), "Windows Server 2019 and later");
  assert.equal(catalogOs("Something else"), "Other");
});

test("release history keeps every version once seen, newest first, with OS, ring and restart", () => {
  const rows = P.parseSenseCatalog(fx("sense-catalog.html"));
  const kb = parseSenseKb(fx("sense-kb.html"));
  const first = mergeSenseReleases([], rows, kb, "2026-11-27");
  assert.deepEqual(first.map((r) => r.version), ["10.8839.26080.2008", "10.8835.26070.1004"]);
  assert.equal(first[0].restart, kb.restart);
  assert.equal(first[1].restart, "");
  assert.equal(first[0].released, "2026-11-11");
  assert.equal(first[0].firstSeen, "2026-11-27");

  // Later the catalog drops the old build and adds a new one with a ring per OS.
  const later = mergeSenseReleases(
    first,
    [
      { version: "10.8840.26090.1000", date: "2026-12-09", title: "Windows 10/11 - Update ... Current Channel (Broad)", channel: "Current Channel (Broad)" },
      { version: "10.8840.26090.1000", date: "2026-12-16", title: "Windows Server 2019+ - Update ...", channel: "Current Channel (Broad)" },
    ],
    null,
    "2026-12-10",
  );
  assert.deepEqual(later.map((r) => r.version), ["10.8840.26090.1000", "10.8839.26080.2008", "10.8835.26070.1004"]);
  assert.deepEqual(later[0].os, ["Windows 10 and 11", "Windows Server 2019 and later"]);
  assert.deepEqual(later[0].rings, ["Current Channel (Broad)"]);
  assert.equal(later[0].released, "2026-12-09");
  assert.equal(later[1].firstSeen, "2026-11-27", "first-seen date survives");
  assert.equal(later[1].restart, kb.restart, "restart text survives a run without the KB page");
});

const seed = [
  {
    id: "telemetry",
    title: "No telemetry until reboot",
    affected: "10.8839.26080.2008",
    stage: "Community reports",
    firstSeen: "2026-11-26",
    communityMatch: "telemetry|pending",
    microsoftMatch: "telemetry|stuck (?:in )?pending",
  },
];
const now = new Date("2026-11-27T12:00:00Z");

test("issue stages: hand-kept floor, then Microsoft acknowledged and Fix announced from the KB text", () => {
  const floor = trackSenseIssues(seed, [], { kb: { ok: true, knownIssues: "" }, now });
  assert.equal(floor[0].stage, "Community reports");

  const kb = { ok: true, ...parseSenseKb(fx("sense-kb.html")) };
  const acked = trackSenseIssues(seed, floor, { kb, latest: "10.8839.26080.2008", now });
  assert.equal(acked[0].stage, "Fix announced");
  assert.equal(acked[0].reached["Microsoft acknowledged"].url, KB_URL);
  assert.equal(acked[0].reached["Community reports"].at, "2026-11-26", "earlier stage dates are kept");
});

test("issue stages: Fix published when Microsoft names a fixed version", () => {
  const kb = { ok: true, knownIssues: "Devices that stop reporting telemetry were fixed in version 10.8840.26090.1000." };
  const out = trackSenseIssues(seed, [], { kb, now });
  assert.equal(out[0].stage, "Fix published");
  assert.match(out[0].reached["Fix published"].note, /10\.8840\.26090\.1000/);
});

test("issue stages: Fix published is inferred only after an acknowledgment, a newer build and a cleared KB", () => {
  const kbAck = { ok: true, knownIssues: "Some devices stop reporting telemetry." };
  const acked = trackSenseIssues(seed, [], { kb: kbAck, latest: "10.8839.26080.2008", now });
  assert.equal(acked[0].stage, "Microsoft acknowledged");
  // Same build, KB cleared: not enough.
  const same = trackSenseIssues(seed, acked, { kb: { ok: true, knownIssues: "There are no known issues in this update." }, latest: "10.8839.26080.2008", now });
  assert.equal(same[0].stage, "Microsoft acknowledged");
  // KB not read this run: never infer from stale text.
  const stale = trackSenseIssues(seed, acked, { kb: { ok: false, stale: true, knownIssues: "" }, latest: "10.8840.26090.1000", now });
  assert.equal(stale[0].stage, "Microsoft acknowledged");
  const fixed = trackSenseIssues(seed, acked, { kb: { ok: true, knownIssues: "There are no known issues in this update." }, latest: "10.8840.26090.1000", now });
  assert.equal(fixed[0].stage, "Fix published");
  assert.match(fixed[0].reached["Fix published"].note, /^Inferred/);
  // And it never moves back.
  const back = trackSenseIssues(seed, fixed, { kb: { ok: true, knownIssues: "" }, now });
  assert.equal(back[0].stage, "Fix published");
});

test("issue stages: a community post must be about the sensor and recent", () => {
  const bare = [{ ...seed[0], stage: "" }];
  const posts = [
    { title: "Telemetry pipeline pending in Splunk", url: "https://x/1", published: "2026-11-26T00:00:00Z" },
    { title: "MsSense stuck pending until reboot after update", url: "https://x/2", published: "2026-11-25T00:00:00Z" },
    { title: "Sense telemetry stopped", url: "https://x/3", published: "2026-10-01T00:00:00Z" },
  ];
  const out = trackSenseIssues(bare, [], { kb: null, posts, now });
  assert.equal(out[0].stage, "Community reports");
  assert.deepEqual(out[0].posts.map((p) => p.url), ["https://x/2"]);
  assert.equal(trackSenseIssues(bare, [], { kb: null, posts: [posts[0]], now })[0].stage, "");
});

test("Windows release health resolved marks Fix published", () => {
  const rows = [{ title: "Defender sensor stops reporting telemetry", detail: "", status: "Resolved KB5131080", url: "https://learn.microsoft.com/x" }];
  const out = trackSenseIssues(seed, [], { kb: null, knownIssues: rows, now });
  assert.equal(out[0].stage, "Fix published");
});

test("curated Sense issues are well formed", () => {
  assert.ok(curated.senseIssues.length >= 1);
  for (const i of curated.senseIssues) {
    assert.ok(i.id && i.title, i.id);
    assert.ok(!i.stage || STAGES.includes(i.stage), i.id);
    for (const r of [i.communityMatch, i.microsoftMatch]) assert.doesNotThrow(() => new RegExp(r, "i"), i.id);
    for (const l of i.links) assert.match(l.url, /^https:\/\//, i.id);
  }
});

test("Sense signal counts recent sensor problem posts only", () => {
  assert.ok(senseContext("KB5005292 fails"));
  assert.ok(!senseContext("Sensible defaults for Intune"));
  const s = senseSignal(
    [
      { title: "MsSense high CPU after update", url: "https://x/a", published: "2026-11-26T00:00:00Z" },
      { title: "MsSense high CPU after update", url: "https://x/a", published: "2026-11-26T00:00:00Z" },
      { title: "New Sense build released", url: "https://x/b", published: "2026-11-26T00:00:00Z" },
    ],
    now,
  );
  assert.equal(s.count, 1);
});
