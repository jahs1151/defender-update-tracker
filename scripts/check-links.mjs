#!/usr/bin/env node
// Check every hand-maintained link.
//  - Each docs/source URL must return HTTP 200.
//  - Each CVE in curated incidents must exist in the MSRC Security Update Guide API.
// Writes site/data/link-report.json (the page hides curated entries whose link failed)
// and exits 1 if anything failed.
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { request, getJson, errorText } from "./lib/http.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = async (p) => JSON.parse(await readFile(join(root, p), "utf8"));

const features = await read("site/data/features.json");
const curated = await read("site/data/curated.json");

const urls = new Map(); // url -> where it is used
const add = (url, where) => {
  if (!url || !/^https?:\/\//.test(url)) return;
  const clean = url.split("#")[0];
  if (!urls.has(clean)) urls.set(clean, []);
  urls.get(clean).push(where);
};
for (const f of features.features) add(f.docs, `feature ${f.id}`);
for (const r of curated.references) add(r.url, `reference ${r.title}`);
for (const i of curated.incidents) if (!/^CVE-/.test(i.id)) add(i.url, `incident ${i.id}`);
add(curated.senseFallback?.url, "sense fallback");

async function check(url) {
  try {
    const res = await request(url, { timeoutMs: 25000, retries: 2, accept: "text/html,*/*" });
    await res.body?.cancel().catch(() => {});
    return { url, status: res.status, ok: res.status === 200 };
  } catch (error) {
    return { url, status: 0, ok: false, error: errorText(error) };
  }
}

async function pool(items, size, fn) {
  const out = [];
  let i = 0;
  await Promise.all(
    Array.from({ length: size }, async () => {
      while (i < items.length) {
        const item = items[i++];
        out.push(await fn(item));
      }
    }),
  );
  return out;
}

const linkResults = await pool([...urls.keys()], 6, check);

const cveResults = await pool(
  curated.incidents.filter((i) => /^CVE-/.test(i.id)),
  3,
  async (i) => {
    try {
      const q = new URLSearchParams({ $filter: `cveNumber eq '${i.id}'`, $top: "1" });
      const json = await getJson(`https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?${q}`, { timeoutMs: 25000 });
      return { url: i.url, id: i.id, ok: (json.value || []).length > 0, status: 200, error: (json.value || []).length ? "" : "CVE not in the Security Update Guide" };
    } catch (error) {
      return { url: i.url, id: i.id, ok: false, status: 0, error: errorText(error) };
    }
  },
);

const failed = [...linkResults, ...cveResults].filter((r) => !r.ok);
const report = {
  checkedAt: new Date().toISOString(),
  links: linkResults.length + cveResults.length,
  failedUrls: failed.map((r) => r.url),
  failures: [
    ...failed.map((r) => ({ kind: "link", url: r.url, status: r.status, error: r.error || `HTTP ${r.status}`, usedBy: urls.get(r.url) || [r.id] })),
  ],
};
await writeFile(join(root, "site", "data", "link-report.json"), `${JSON.stringify(report, null, 1)}\n`);

console.log(`Checked ${report.links} links.`);
for (const f of report.failures) console.log(`FAIL ${f.kind} ${f.url}: ${f.error}${f.usedBy ? ` (used by ${f.usedBy.join(", ")})` : ""}`);
if (report.failures.length) process.exitCode = 1;
