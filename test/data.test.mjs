import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (p) => JSON.parse(readFileSync(new URL(`../site/data/${p}`, import.meta.url), "utf8"));
const features = read("features.json");
const curated = read("curated.json");
const pulse = read("pulse.json");

test("news- or blog-sourced features are marked Reported", () => {
  for (const f of features.features) {
    assert.match(f.docs, /^https:\/\//, f.id);
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

test("the site carries no OMA-URI or policy values", () => {
  const app = readFileSync(new URL("../site/assets/app.js", import.meta.url), "utf8");
  assert.doesNotMatch(app, /\.\/Vendor\/MSFT|\.\/Device\/Vendor/);
});

test("the header row class .bar is styled once (a chart class named .bar once turned it into a tall blue column)", () => {
  const css = readFileSync(new URL("../site/assets/styles.css", import.meta.url), "utf8");
  assert.equal((css.match(/(^|[\s,}])\.bar\s*[{,:]/g) || []).length, 1);
});
