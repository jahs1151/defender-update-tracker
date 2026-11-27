// Change alerts: lines, webhook bodies, history and the RSS feed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { changeLine, appendHistory, buildFeed, webhookKind, webhookBody } from "../scripts/lib/notify.mjs";
import { diffPulse } from "../scripts/lib/diff.mjs";

const changes = [
  { field: "Security intelligence", kind: "changed", from: "1.463.495.0", to: "1.463.497.0" },
  { field: "Detection alerts", kind: "added", to: "Trojan:MSIL/XWorm.D!MTB in 1.463.497.0 (named in BleepingComputer: XWorm)" },
];

test("change lines", () => {
  assert.equal(changeLine(changes[0]), "Security intelligence: 1.463.495.0 → 1.463.497.0");
  assert.match(changeLine(changes[1]), /^Detection alerts: new Trojan/);
  assert.equal(changeLine({ field: "Open known issues", kind: "removed", from: "X" }), "Open known issues: no longer listed X");
});

test("history grows only on a run that changed content", () => {
  const at = "2026-11-27T16:27:02.172Z";
  const changed = { checkedAt: at, contentChangedAt: at, changes };
  const h1 = appendHistory([], changed);
  assert.equal(h1.length, 1);
  assert.equal(appendHistory(h1, changed), h1, "same run twice is not added twice");
  assert.equal(appendHistory(h1, { checkedAt: "2026-11-27T17:27:00Z", contentChangedAt: at, changes }), h1);
  assert.equal(appendHistory(Array.from({ length: 50 }, (_, i) => ({ at: `2026-01-${i}`, lines: [] })), { ...changed, checkedAt: "2026-12-01T00:00:00Z", contentChangedAt: "2026-12-01T00:00:00Z" }).length, 50);
});

test("RSS feed is valid-looking, escaped, and shows UTC and Chicago time", () => {
  const xml = buildFeed([{ at: "2026-11-27T16:27:02.172Z", lines: ["A <b> & \"c\"", "second"] }]);
  assert.match(xml, /^<\?xml version="1.0"/);
  assert.match(xml, /<title>A &lt;b&gt; &amp; &quot;c&quot; \(\+1 more\)<\/title>/);
  assert.match(xml, /<pubDate>Fri, 27 Nov 2026 16:27:02 GMT<\/pubDate>/);
  assert.match(xml, /16:27 UTC · 27 Nov 2026, 10:27 CST/);
  assert.doesNotMatch(xml, /<b>/);
  assert.match(buildFeed([]), /<channel>/);
});

test("webhook kind from the host", () => {
  assert.equal(webhookKind("https://hooks.slack.com/services/T/B/x"), "slack");
  assert.equal(webhookKind("https://contoso.webhook.office.com/webhookb2/x"), "teams");
  assert.equal(webhookKind("https://prod-01.westus.logic.azure.com/workflows/x"), "teams");
  assert.equal(webhookKind("https://example.com/hook"), "json");
  assert.equal(webhookKind("not a url"), "invalid");
});

test("webhook bodies", () => {
  const lines = changes.map(changeLine);
  assert.match(webhookBody("slack", lines, "2026-11-27T16:27:02Z").text, /• Security intelligence/);
  const teams = webhookBody("teams", lines, "2026-11-27T16:27:02Z");
  assert.equal(teams.attachments[0].contentType, "application/vnd.microsoft.card.adaptive");
  assert.equal(teams.attachments[0].content.body.length, 3);
  assert.deepEqual(webhookBody("json", lines, "2026-11-27T16:27:02Z").changes, lines);
});

test("fields new in schema 4 are not reported as new on the first run after an upgrade", () => {
  const old = { sections: { sense: { data: { latest: { version: "10.8839.26080.2008" } } } } };
  const next = {
    sections: {
      sense: { data: { latest: { version: "10.8839.26080.2008" }, releases: [{ version: "10.8839.26080.2008" }], kb: { ok: true, knownIssues: "" }, issues: [{ title: "X", stage: "Community reports" }] } },
      threats: { data: { alerts: [{ detection: "D", version: "1", threat: "T", story: { source: "S" } }], coverage: [] } },
    },
  };
  assert.deepEqual(diffPulse(old, next), []);
  // Next run: a stage moves and a release and alert appear; an alert ageing out is not a change.
  const after = structuredClone(next);
  after.sections.sense.data.issues[0].stage = "Microsoft acknowledged";
  after.sections.sense.data.releases.unshift({ version: "10.8840.26090.1000" });
  after.sections.threats.data.alerts = [];
  const lines = diffPulse(next, after).map(changeLine);
  assert.deepEqual(lines, ["Sense releases: new 10.8840.26090.1000", "Sense issue: X: Community reports → Microsoft acknowledged"]);
});
