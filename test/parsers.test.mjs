// Parser tests. Fixtures are trimmed copies shaped like the live Microsoft pages,
// so a layout change on Microsoft's side shows up as a failing test or a failed source.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as P from "../scripts/lib/parsers.mjs";
import { diffPulse, contentKey } from "../scripts/lib/diff.mjs";

const fx = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");

test("definitions page versions", () => {
  const d = P.parseDefinitions(fx("definitions.html"));
  assert.deepEqual(
    { si: d.securityIntelligence, engine: d.engine, platform: d.platform, raw: d.releasedRaw },
    { si: "1.463.322.0", engine: "1.1.26100.4", platform: "4.18.26100.4", raw: "11/16/2026 2:41:33 AM" },
  );
  assert.equal(P.parseDefinitions("<html>maintenance</html>"), null);
});

test("definitions clock time zone is decided from evidence", () => {
  // Seen live on 16 Nov 2026 ~03:45 UTC: "2:41:33 AM" as Pacific would be 10:41 UTC, in the future.
  const future = P.resolveDefinitionsClock("11/16/2026 2:41:33 AM", "", "", new Date("2026-11-16T03:45:00Z"));
  assert.equal(future.zone, "UTC");
  assert.equal(future.releasedAt, "2026-11-16T02:41:33.000Z");
  assert.match(future.basis, /^Verified/);

  const byHeader = P.resolveDefinitionsClock("11/15/2026 9:05:12 PM", "", "Sun, 15 Nov 2026 21:20:00 GMT", new Date("2026-11-17T00:00:00Z"));
  assert.equal(byHeader.zone, "UTC");
  assert.match(byHeader.basis, /within 15 min/);

  const pacific = P.resolveDefinitionsClock("11/15/2026 9:05:12 PM", "", "Mon, 16 Nov 2026 05:15:00 GMT", new Date("2026-11-17T00:00:00Z"));
  assert.equal(pacific.zone, "America/Los_Angeles");
  assert.equal(pacific.releasedAt, "2026-11-16T05:05:12.000Z");

  // A header 3 hours off proves nothing.
  const weak = P.resolveDefinitionsClock("11/16/2026 2:41:33 AM", "", "Sun, 15 Nov 2026 23:50:30 GMT", new Date("2026-11-17T00:00:00Z"));
  assert.equal(weak.zone, "UTC");
  assert.match(weak.basis, /^Read as UTC. Not provable/);

  assert.equal(P.resolveDefinitionsClock("11/15/2026 9:05:12 PM", "UTC", "").basis, "The page labels its clock UTC.");
});

test("download redirect parameters", () => {
  const v = P.parseDownloadUrl("https://definitionupdates.microsoft.com/packages/content/mpam-fe.exe?packageType=Signatures&packageVersion=1.463.320.0&arch=amd64&engineVersion=1.1.26100.4");
  assert.deepEqual(v, { packageVersion: "1.463.320.0", engineVersion: "1.1.26100.4" });
});

test("monthly platform and engine releases", () => {
  const rows = P.parseProductUpdates(fx("product-updates.html"));
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0], {
    label: "February 2026",
    platform: "4.18.26020.6",
    engine: "1.1.26020.3",
    securityIntelligence: "1.447.2.0",
    released: "2026-03-25",
    supportPhase: "Security and Critical Updates",
  });
  assert.equal(rows[1].released, "2026-02-10");
});

test("Defender for Endpoint what's new table keeps Windows rows", () => {
  const items = P.parseMdeWhatsNew(fx("mde-whats-new.html"), "https://learn.microsoft.com/en-us/defender-endpoint/whats-new-in-microsoft-defender-endpoint");
  assert.deepEqual(items.map((i) => i.name), ["Local AI agent discovery on Windows and macOS"]);
  assert.equal(items[0].stage, "GA");
  assert.equal(items[0].url, "https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview");
});

test("version month code", () => {
  assert.equal(P.versionMonth("4.18.26100.4") - P.versionMonth("4.18.26080.3"), 2);
  assert.equal(P.versionMonth("1.1.26010.1") - P.versionMonth("1.1.25110.1"), 2);
  assert.equal(P.versionMonth("garbage"), null);
});

test("release health known issues", () => {
  const rows = P.parseReleaseHealth(fx("release-health.html"), "https://example.com/rh", ["win11"], "Windows 11 24H2");
  assert.equal(rows.length, 2);
  assert.equal(rows[0].title, "Microsoft Defender Antivirus might fail to start after update");
  assert.equal(rows[0].scope, "security");
  assert.equal(rows[0].status, "Confirmed");
  assert.equal(rows[0].updated, "2026-11-12");
  assert.equal(rows[0].url, "https://example.com/rh#3721msgdesc");
  assert.equal(rows[1].scope, "windows");
});

test("RSS feed and endpoint news filter", () => {
  const items = P.parseFeed(fx("feed.xml"), "Test");
  assert.equal(items.length, 3);
  assert.equal(items[0].published, "2026-11-15T18:00:00.000Z");
  assert.equal(items[0].summary, "Attackers abuse Defender on Windows 11.");
  const kept = items.filter(P.isEndpointNews).map((i) => i.url);
  assert.deepEqual(kept, ["https://example.com/a"]);
});

test("detection changelog", () => {
  const c = P.parseChangelog(fx("changelog.html"));
  assert.equal(c.version, "1.463.322.0");
  assert.equal(c.releasedRaw, "11/16/2026 2:36:17 AM");
  assert.equal(c.rows.length, 3);
  assert.equal(c.rows.filter((r) => r.change === "updated").length, 1);
  assert.match(c.rows[0].url, /^https:\/\/www\.microsoft\.com\/en-us\/wdsi\/threats\//);
});

test("Sense build from the Update Catalog", () => {
  const rows = P.parseSenseCatalog(fx("sense-catalog.html"));
  assert.equal(rows[0].version, "10.8839.26080.2008");
  assert.equal(rows[0].date, "2026-11-11");
});

test("KEV filter keeps recent Microsoft Windows and endpoint entries", () => {
  const json = {
    vulnerabilities: [
      { cveID: "CVE-2026-1", vendorProject: "Microsoft", product: "Defender", vulnerabilityName: "Microsoft Defender EoP", dateAdded: "2026-10-01", shortDescription: "x", dueDate: "2026-10-22", knownRansomwareCampaignUse: "Unknown" },
      { cveID: "CVE-2026-2", vendorProject: "Microsoft", product: "Windows", vulnerabilityName: "Windows CLFS EoP", dateAdded: "2026-09-01", shortDescription: "Windows Server 2025", dueDate: "", knownRansomwareCampaignUse: "Known" },
      { cveID: "CVE-2026-3", vendorProject: "Apple", product: "iOS", vulnerabilityName: "x", dateAdded: "2026-10-01", shortDescription: "x", dueDate: "", knownRansomwareCampaignUse: "" },
      { cveID: "CVE-2020-4", vendorProject: "Microsoft", product: "Windows", vulnerabilityName: "old", dateAdded: "2020-01-01", shortDescription: "x", dueDate: "", knownRansomwareCampaignUse: "" },
    ],
  };
  const rows = P.filterKev(json, 12, new Date("2026-11-16T00:00:00Z"));
  assert.deepEqual(rows.map((r) => r.cve), ["CVE-2026-1", "CVE-2026-2"]);
  assert.equal(rows[0].endpointSecurity, true);
  assert.deepEqual(rows[1].os, ["srv2025"]);
});

test("MSRC month summary", () => {
  const s = P.summarizeMsrc({
    month: "2026-Nov",
    osRows: {
      win11: [
        { cveNumber: "CVE-1", severity: "Important" },
        { cveNumber: "CVE-2", severity: "Critical" },
        { cveNumber: "CVE-2", severity: "Critical" },
      ],
      srv2025: [{ cveNumber: "CVE-2", severity: "Critical" }, { cveNumber: "CVE-3", severity: "Important" }],
    },
    endpointRows: [
      { cveNumber: "CVE-9", cveTitle: "Microsoft Defender Elevation of Privilege Vulnerability", baseScore: "7.8", releaseDate: "2026-11-10T08:00:00-08:00" },
      { cveNumber: "CVE-9", cveTitle: "dup" },
      { cveNumber: "CVE-8", cveTitle: "Microsoft Defender for Endpoint for Android Spoofing" },
      { cveNumber: "CVE-7", cveTitle: "Firefox bug", isMariner: true },
    ],
    endpointSeverity: { "CVE-9": "Important" },
  });
  assert.equal(s.windowsTotal, 3);
  assert.equal(s.critical, 1);
  assert.deepEqual(s.perOs.win11, { total: 2, critical: 1 });
  assert.deepEqual(s.endpoint.map((r) => [r.cve, r.severity, r.released]), [["CVE-9", "Important", "2026-11-10T16:00:00.000Z"]]);
});

test("diff reports version changes and ignores timestamps", () => {
  const mk = (si, at) => ({ checkedAt: at, sections: { intelligence: { checkedAt: at, data: { securityIntelligence: si, engine: "1.1.1.1", platform: "4.18.1.1" } } } });
  assert.equal(contentKey(mk("1.1.1.0", "a")), contentKey(mk("1.1.1.0", "b")));
  const d = diffPulse(mk("1.463.1.0", "a"), mk("1.463.2.0", "b"));
  assert.deepEqual(d, [{ field: "Security intelligence", kind: "changed", from: "1.463.1.0", to: "1.463.2.0" }]);
});

test("offline image page versions", () => {
  const html = `<p>Defender package version: <strong>1.463.217.0</strong></p><p>Platform version: <strong>4.18.26100.4</strong></p>
    <p>Engine version: <strong>1.1.26100.4</strong></p><p>Security intelligence version: <strong>1.463.217.0</strong></p>`;
  assert.deepEqual(P.parseWimPage(html), { packageVersion: "1.463.217.0", platform: "4.18.26100.4", engine: "1.1.26100.4", securityIntelligence: "1.463.217.0" });
});

test("bad-detection chatter matcher", () => {
  assert.ok(P.isBadDetectionChatter("Defender false positive quarantines Chrome after 1.463.322.0"));
  assert.ok(P.isBadDetectionChatter("SenseIR.exe flagged as reverse shell"));
  assert.ok(!P.isBadDetectionChatter("Patch Tuesday fixes 60 bugs"));
});

test("Reddit posts are filtered and cleaned", () => {
  const json = {
    data: [
      { title: "MDE flagged our backup agent", selftext: "Defender **quarantined** it", permalink: "/r/sysadmin/comments/a/", created_utc: 1763251200, subreddit: "sysadmin", author: "x" },
      { title: "Printer driver help", selftext: "nothing about AV", permalink: "/r/sysadmin/comments/b/", created_utc: 1763251100, subreddit: "sysadmin", author: "y" },
      { title: "[removed]", selftext: "", permalink: "/r/sysadmin/comments/c/", created_utc: 1, author: "z" },
      { title: "Defender on macOS crash", selftext: "macOS only", permalink: "/r/sysadmin/comments/d/", created_utc: 2, author: "w" },
    ],
  };
  const posts = P.parseRedditPosts(json, "sysadmin", true);
  assert.deepEqual(posts.map((p) => p.url), ["https://www.reddit.com/r/sysadmin/comments/a/"]);
  assert.equal(posts[0].summary, "Defender quarantined it");
  assert.equal(posts[0].published, "2025-11-16T00:00:00.000Z");
});
