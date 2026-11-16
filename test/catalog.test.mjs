import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (p) => JSON.parse(readFileSync(new URL(`../site/data/${p}`, import.meta.url), "utf8"));
const catalog = read("catalog.json");
const curated = read("curated.json");
const pulse = read("pulse.json");

test("every policy has the fields the page shows", () => {
  for (const p of catalog.policies) {
    for (const k of ["id", "area", "name", "summary", "intunePath", "omaUri", "dataType", "value", "os", "docs"]) {
      assert.ok(p[k] !== undefined && p[k] !== "", `${p.id} is missing ${k}`);
    }
    assert.ok(catalog.areaLabels[p.area], `${p.id} has unknown area ${p.area}`);
    assert.match(p.docs, /^https:\/\//, `${p.id} docs must be a URL`);
  }
});

test("ids are unique", () => {
  const ids = catalog.policies.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("ADMX-backed settings use String values with <enabled/>", () => {
  const admx = catalog.policies.filter((p) => /\/(Autoplay|ADMX_[^/]+)\/|\/BitLocker\/(EncryptionMethodByDriveType|RemovableDrivesRequireEncryption|SystemDrivesRecoveryOptions)$/.test(p.omaUri));
  assert.ok(admx.length >= 6);
  for (const p of admx) {
    assert.equal(p.dataType, "String", `${p.id} must be String`);
    assert.match(p.value, /^<(enabled|disabled)\/>/, `${p.id} value must be an ADMX string`);
  }
});

test("firewall items list all three profiles", () => {
  for (const id of ["fw-enable", "fw-merge"]) {
    const p = catalog.policies.find((x) => x.id === id);
    const profiles = (p.omaUris || []).map((u) => u.split("/")[5]);
    assert.deepEqual(profiles.sort(), ["DomainProfile", "PrivateProfile", "PublicProfile"]);
  }
});

test("gradual rollout channel settings exist", () => {
  const uris = new Set(catalog.policies.map((p) => p.omaUri));
  for (const n of ["EngineUpdatesChannel", "PlatformUpdatesChannel", "SecurityIntelligenceUpdatesChannel"]) {
    assert.ok(uris.has(`./Vendor/MSFT/Defender/Configuration/${n}`), n);
  }
});

test("ThreatSeverityDefaultAction item says it allows threats and carries a warning", () => {
  const p = catalog.policies.find((x) => x.id === "threat-action-hold");
  assert.match(p.name, /allow/i);
  assert.ok(p.warning);
});

test("news- or blog-sourced features are marked Reported", () => {
  for (const f of catalog.features) {
    if (!/learn\.microsoft\.com/.test(f.docs)) assert.equal(f.status, "Reported", f.id);
  }
});

test("curated incidents are well formed", () => {
  for (const i of curated.incidents) {
    assert.match(i.url, /^https:\/\//);
    assert.match(i.date, /^\d{4}-\d{2}-\d{2}$/);
  }
});

test("pulse.json has every section the page expects", () => {
  for (const k of ["packages", "intelligence", "productUpdates", "changelog", "sense", "patchTuesday", "kev", "knownIssues", "intune", "mde", "news"]) {
    assert.ok(pulse.sections[k], `missing section ${k}`);
  }
  assert.ok(!Number.isNaN(Date.parse(pulse.checkedAt)));
});
