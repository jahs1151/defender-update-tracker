// Microsoft threat catalog: result page parser, prefix walk, shard names, browser-side search.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseCatalogPage, isoDate, readQuery, children, CUT_OFF } from "../scripts/lib/catalog.mjs";
import { searchCatalog, shardOf, shardForQuery, catalogSearchUrl, entryUrl, longDate } from "../site/assets/catalog.js";

const page = readFileSync(new URL("./fixtures/catalog-bearfoos.html", import.meta.url), "utf8");

test("a real result page: name, severity, updated date, count", () => {
  const p = parseCatalogPage(page);
  assert.equal(p.total, 1);
  assert.deepEqual(p.rows, [{ name: "Trojan:Win32/Bearfoos", severity: "s", updated: "2024-04-24" }]);
});

test("dates", () => {
  assert.equal(isoDate("Apr 24, 2024"), "2024-04-24");
  assert.equal(isoDate("Updated on  Sep 3, 2019"), "2019-09-03");
  assert.equal(isoDate("garbage"), "");
  assert.equal(longDate("2024-04-24"), "Apr 24, 2024");
});

const makePage = (names, total) =>
  `<span id="totalCount">${total ?? names.length}</span> entries found.` +
  names.map((n) => `<h2 class="c-heading-5" id="threatLink"><a class="c-hyperlink" href="malware-encyclopedia-description?Name=${n}">${n}</a></h2><div id="threatPubDate">Updated on  Jan 2, 2020</div><div id="threatLevel"><span name="high">high</span></div>`).join("") +
  "</section>";

test("a small prefix is read page by page and non-Windows names are dropped", async () => {
  const all = Array.from({ length: 25 }, (_, i) => `Trojan:Win32/Foo${i}`);
  all.push("Trojan:Linux/Foo99");
  const pages = [all.slice(0, 20), all.slice(20)];
  const asked = [];
  const r = await readQuery("Trojan:Win32/Foo", async (q, p) => (asked.push(p), makePage(pages[p - 1] || [], all.length)));
  assert.equal(r.cut, false);
  assert.equal(r.rows.length, 25);
  assert.ok(!r.rows.some((x) => /Linux/.test(x.name)));
  assert.deepEqual(asked, [1, 2]);
  assert.equal(r.rows[0].severity, "h");
});

test("a prefix at the cut-off is split, not paged", async () => {
  const asked = [];
  const r = await readQuery("Trojan:Win32/A", async (q, p) => (asked.push(p), makePage(["Trojan:Win32/A"], CUT_OFF + 26)));
  assert.equal(r.cut, true);
  assert.deepEqual(asked, [1]);
  assert.equal(r.rows.length, 1);
  assert.ok(children("Trojan:Win32/A").includes("Trojan:Win32/Ab"));
  assert.ok(children("X").includes("X9"));
});

test("shards: by the first letter of the family", () => {
  assert.equal(shardOf("Trojan:Win32/Bearfoos"), "b");
  assert.equal(shardOf("Trojan:Win32/7ev3n.A"), "7");
  assert.equal(shardOf("Trojan:Win32/_x"), "_");
  assert.equal(shardForQuery("Bearfoos"), "b");
  assert.equal(shardForQuery("Trojan:Win32/Bear"), "b");
  assert.equal(shardForQuery("win32/wacatac"), "w");
});

const rows = [
  ["Trojan:Win32/Bearfoos", "s", "2024-04-24"],
  ["Trojan:Win32/Bearfoos!MTB", "s", "2023-04-12"],
  ["Trojan:Win32/Bearfoos.B", "s", "2025-05-20"],
  ["PUA:Win32/Pearfoos", "l", "2020-01-01"],
];

test("search: exact name first, partial and punctuation tolerant", () => {
  const r = searchCatalog(rows, "Trojan:Win32/Bearfoos");
  assert.equal(r.rows[0].name, "Trojan:Win32/Bearfoos");
  assert.equal(r.rows[0].severity, "severe");
  assert.equal(r.rows[0].updated, "2024-04-24");
  assert.equal(searchCatalog(rows, "bearfoos").total, 3);
  assert.equal(searchCatalog(rows, "BEARFOOS MTB").total, 1);
  assert.equal(searchCatalog(rows, "bearfoos!mtb").total, 1);
  assert.equal(searchCatalog(rows, "foos").total, 4);
  assert.equal(searchCatalog(rows, "zz").tooShort, true);
  assert.equal(searchCatalog(rows, "nothing").total, 0);
});

test("links", () => {
  assert.equal(catalogSearchUrl("Bearfoos"), "https://www.microsoft.com/en-us/wdsi/threats/threat-search?query=Bearfoos");
  assert.equal(entryUrl("Trojan:Win32/Bearfoos!MTB"), "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/Bearfoos!MTB");
});
