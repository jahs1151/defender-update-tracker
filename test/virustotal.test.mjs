// VirusTotal lookups: no key, limits, 24-hour cache, gaps, and the key never leaving the request header.
import { test } from "node:test";
import assert from "node:assert/strict";
import { vtLookup, parseVtFile } from "../scripts/lib/virustotal.mjs";

const now = new Date("2026-11-27T18:00:00Z");
const file = (ms, others) => ({
  data: {
    attributes: {
      type_description: "Win32 EXE",
      last_analysis_stats: { malicious: others + (ms ? 1 : 0) },
      last_analysis_results: {
        Microsoft: ms ? { category: "malicious", result: "Trojan:Win32/Wacatac.B!ml" } : { category: "undetected", result: null },
        ...Object.fromEntries(Array.from({ length: others }, (_, i) => [`E${i}`, { category: "malicious", result: "x" }])),
        Clean: { category: "undetected", result: null },
      },
    },
  },
});

test("a gap is other engines detecting what Microsoft does not", () => {
  assert.equal(parseVtFile(file(false, 5)).gap, true);
  assert.equal(parseVtFile(file(true, 5)).gap, false);
  assert.equal(parseVtFile(file(true, 5)).microsoft, "Trojan:Win32/Wacatac.B!ml");
  assert.equal(parseVtFile(file(false, 0)).gap, false);
});

test("no key: nothing is fetched and the status says so", async () => {
  let calls = 0;
  const r = await vtLookup([{ hash: "a".repeat(64) }], { key: "", now, fetchImpl: async () => calls++ });
  assert.deepEqual([r.status, calls], ["no-key", 0]);
});

test("limits: 4 a minute, 500 a day, answers kept 24 hours, key only in the header", async () => {
  const seen = [];
  const waits = [];
  const fetchImpl = async (url, opts) => {
    seen.push({ url, key: opts.headers["x-apikey"] });
    if (url.endsWith("b".repeat(64))) return { status: 404, ok: false };
    return { status: 200, ok: true, json: async () => file(false, 3) };
  };
  const rows = [
    { hash: "a".repeat(64) },
    { hash: "b".repeat(64) },
    { hash: "c".repeat(64), vtResult: { found: true, checkedAt: "2026-11-27T10:00:00.000Z" } },
  ];
  const r = await vtLookup(rows, { key: "SECRET", now, fetchImpl, sleep: async (ms) => waits.push(ms) });
  assert.equal(seen.length, 2, "the hash checked 8 hours ago is not asked again");
  assert.ok(seen.every((s) => s.key === "SECRET" && !s.url.includes("SECRET")));
  assert.deepEqual(waits, [15000], "15 seconds between lookups is 4 a minute");
  assert.equal(r.rows[0].vtResult.gap, true);
  assert.equal(r.rows[1].vtResult.found, false);
  assert.ok(!JSON.stringify(r).includes("SECRET"), "the key is never in the result");
  assert.deepEqual(r.budget, { day: "2026-11-27", used: 2 });
  const capped = await vtLookup([{ hash: "d".repeat(64) }], { key: "SECRET", now, budget: { day: "2026-11-27", used: 500 }, fetchImpl, sleep: async () => {} });
  assert.equal(capped.status, "limited");
  assert.equal(capped.rows[0].vtResult, undefined);
});

test("a rejected key stops the run", async () => {
  const r = await vtLookup([{ hash: "a".repeat(64) }, { hash: "b".repeat(64) }], { key: "BAD", now, fetchImpl: async () => ({ status: 401, ok: false }), sleep: async () => {} });
  assert.equal(r.status, "rejected");
});
