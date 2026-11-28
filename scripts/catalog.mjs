#!/usr/bin/env node
// Build or extend the static Microsoft threat catalog index: site/data/catalog/<shard>.json plus _state.json.
//   node scripts/catalog.mjs --minutes 4          walk the catalog for 4 minutes, then save and stop (resumable)
//   node scripts/catalog.mjs --minutes 4 --new    also look up changelog names the index does not have yet
// Polite by design: 3 requests at a time, a pause between each, and a stop at the first sign of blocking.
import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { request } from "./lib/http.mjs";
import { SEARCH_URL, TYPES, PLATFORMS, readQuery, children, shardOf, toRow } from "./lib/catalog.mjs";
import { isWindowsDetection } from "./lib/platform.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(root, "site", "data", "catalog");
const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i < 0 ? fallback : process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[i + 1] : true;
};
const minutes = Number(arg("minutes", 4));
const concurrency = Number(arg("concurrency", 3));
const pause = Number(arg("pause", 350));
const dir = arg("dir", DIR);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const readJson = async (p, f) => JSON.parse(await readFile(p, "utf8").catch(() => "null")) ?? f;

async function fetchPage(query, page) {
  const res = await request(`${SEARCH_URL}?query=${encodeURIComponent(query)}${page > 1 ? `&page=${page}` : ""}`, { retries: 2, timeoutMs: 25000 });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  await sleep(pause);
  return res.text();
}

async function loadShards() {
  const shards = new Map();
  for (const f of await readdir(dir).catch(() => [])) {
    if (!/^[a-z0-9_]\.json$/.test(f)) continue;
    const j = await readJson(join(dir, f), { rows: [] });
    shards.set(f[0], new Map(j.rows.map((r) => [r[0], r])));
  }
  return shards;
}

async function saveShards(shards, touched) {
  await mkdir(dir, { recursive: true });
  for (const c of touched) {
    const rows = [...shards.get(c).values()].sort((a, b) => a[0].localeCompare(b[0]));
    // One row per line keeps git diffs small.
    await writeFile(join(dir, `${c}.json`), `{"shard":"${c}","rows":[\n${rows.map((r) => JSON.stringify(r)).join(",\n")}\n]}\n`);
  }
}

const shards = await loadShards();
const touched = new Set();
const add = (r) => {
  if (!isWindowsDetection(r.name)) return;
  const c = shardOf(r.name);
  if (!shards.has(c)) shards.set(c, new Map());
  shards.get(c).set(r.name, toRow(r));
  touched.add(c);
};

let state = await readJson(join(dir, "_state.json"), null);
if (!state || arg("reset", false)) {
  const queue = [];
  for (const t of [...new Set(TYPES)]) for (const p of PLATFORMS) queue.push(`${t}:${p}/`);
  state = { version: 1, startedAt: new Date().toISOString(), completedAt: "", queue, requests: 0, failed: [] };
}

// A finished walk is repeated every 30 days (in 5-minute slices) so updated dates and new entries come in.
if (state.completedAt && !state.queue.length && Date.now() - Date.parse(state.completedAt) > 30 * 86400000) {
  state.queue = [...new Set(TYPES)].flatMap((t) => PLATFORMS.map((p) => `${t}:${p}/`));
  state.completedAt = "";
  state.startedAt = new Date().toISOString();
}

const deadline = Date.now() + minutes * 60000;
let failures = 0;
let stop = false;
let done = 0;
async function worker() {
  while (!stop && Date.now() < deadline && state.queue.length) {
    const prefix = state.queue.shift();
    try {
      const r = await readQuery(prefix, async (q, p) => {
        state.requests += 1;
        return fetchPage(q, p);
      });
      failures = 0;
      r.rows.forEach(add);
      if (r.cut) state.queue.push(...children(prefix));
      done += 1;
      if (done % 100 === 0) console.log(`  ${done} prefixes · ${state.queue.length} queued · ${[...shards.values()].reduce((n, m) => n + m.size, 0)} names · ${state.requests} requests`);
    } catch (e) {
      state.queue.unshift(prefix);
      failures += 1;
      console.log(`  ${prefix}: ${e.message} (${failures})`);
      if (failures >= 6) {
        stop = true;
        console.log("Too many failures in a row; stopping so Microsoft's site is not hammered. State saved.");
      } else await sleep(2000 * failures);
    }
  }
}

// Names the index lacks: ask for each one directly (changelog names are mostly newer than the catalog, so most return nothing).
if (arg("new", false)) {
  const det = await readJson(join(root, "site", "data", "detections.json"), { versions: {} });
  const have = new Set([...shards.values()].flatMap((m) => [...m.keys()]));
  state.asked = state.asked || {};
  const todo = [...new Set(Object.values(det.versions).flatMap((v) => v.names || []))].filter((n) => isWindowsDetection(n) && !have.has(n) && !state.asked[n]).slice(0, 60);
  for (const n of todo) {
    if (Date.now() > deadline) break;
    try {
      (await readQuery(n, fetchPage)).rows.forEach(add);
      state.asked[n] = new Date().toISOString().slice(0, 10);
    } catch (e) {
      console.log(`  ${n}: ${e.message}`);
      break;
    }
  }
  // Keep the memory of asked names to the changelog window.
  const live = new Set(Object.values(det.versions).flatMap((v) => v.names || []));
  for (const k of Object.keys(state.asked)) if (!live.has(k)) delete state.asked[k];
  console.log(`  looked up ${todo.length} names not yet in the index`);
}

async function save() {
  if (!state.queue.length && !state.completedAt) state.completedAt = new Date().toISOString();
  await saveShards(shards, touched);
  touched.clear();
  state.names = [...shards.values()].reduce((n, m) => n + m.size, 0);
  state.updatedAt = new Date().toISOString();
  // The queue can be long: keep it compact, one prefix per line.
  await writeFile(join(dir, "_state.json"), `{"version":${state.version},"startedAt":"${state.startedAt}","completedAt":"${state.completedAt}","updatedAt":"${state.updatedAt}","requests":${state.requests},"names":${state.names},"asked":${JSON.stringify(state.asked || {})},"seeded":${JSON.stringify(state.seeded || {})},"queue":[\n${state.queue.map((q) => JSON.stringify(q)).join(",\n")}\n]}\n`);
}
const saver = setInterval(() => save().catch(() => {}), 120000);
// Families named in the last 30 days of changelogs (and any given with --seed "Trojan:Win32/Bearfoos,..."): the most
// searched names, so they are read first. One prefix query returns the family and all its variants.
if (arg("families", false) || arg("seed", false)) {
  const det = await readJson(join(root, "site", "data", "detections.json"), { versions: {} });
  state.seeded = state.seeded || {};
  const given = String(arg("seed", "") === true ? "" : arg("seed", "")).split(",").map((x) => x.trim()).filter(Boolean);
  const fams = new Set(given);
  if (arg("families", false)) {
    for (const v of Object.values(det.versions)) for (const n of v.names || []) {
      const m = /^([^:\/]+:[^\/]+\/[^.!]+)/.exec(n);
      if (m && isWindowsDetection(n)) fams.add(m[1]);
    }
  }
  const live = [...fams].filter((f) => !state.seeded[f]);
  console.log(`  ${live.length} family prefixes to read first`);
  let next = 0;
  const seedWorker = async () => {
    while (!stop && Date.now() < deadline && next < live.length) {
      const f = live[next++];
      try {
        const r = await readQuery(f, async (q, p) => {
          state.requests += 1;
          return fetchPage(q, p);
        });
        r.rows.forEach(add);
        if (r.cut) state.queue.push(...children(f));
        state.seeded[f] = new Date().toISOString().slice(0, 10);
        failures = 0;
      } catch (e) {
        failures += 1;
        console.log(`  ${f}: ${e.message} (${failures})`);
        if (failures >= 6) stop = true;
        else await sleep(2000 * failures);
      }
      if (next % 100 === 0) console.log(`  families ${next}/${live.length} · ${[...shards.values()].reduce((n, m) => n + m.size, 0)} names`);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, seedWorker));
  // Memory of read families is kept for the changelog window only.
  for (const k of Object.keys(state.seeded)) if (!fams.has(k) && !given.length) delete state.seeded[k];
}

await Promise.all(Array.from({ length: concurrency }, worker));
clearInterval(saver);
await save();
const total = state.names;
console.log(`catalog: ${total} Windows names in ${shards.size} shards · ${state.queue.length} prefixes left · ${state.completedAt ? "complete " + state.completedAt : "walk not finished"} · ${state.requests} requests`);
