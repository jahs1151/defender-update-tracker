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

test("index.html asks for versioned CSS and JS so phones pick up a new deploy", () => {
  const html = readFileSync(new URL("../site/index.html", import.meta.url), "utf8");
  assert.match(html, /assets\/styles\.css\?v=__V__/);
  assert.match(html, /assets\/app\.js\?v=__V__/);
});

test("Detections tab: linked at #threats, owns the detection sections, and the jump row exists", () => {
  const html = readFileSync(new URL("../site/index.html", import.meta.url), "utf8");
  const app = readFileSync(new URL("../site/assets/app.js", import.meta.url), "utf8");
  assert.match(html, /<a href="#threats" data-tab="threats">Detections<\/a>/);
  assert.match(html, /<nav class="wrap jump" id="jump"/);
  assert.match(app, /const TABS = \[[^\]]*"threats"/);
  for (const id of ["changelog", "si-trend", "detection-alerts", "vendor-coverage", "kev-coverage", "hashes"]) assert.match(app, new RegExp(`"?${id}"?: "threats"`), id);
});
