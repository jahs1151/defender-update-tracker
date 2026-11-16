#!/usr/bin/env node
// Prints short excerpts of the live source pages to the log, for fixing parsers when
// Microsoft changes a layout. Run from Actions → "Inspect sources" → Run workflow.
import { getText, getJson } from "./lib/http.mjs";
import { plain } from "./lib/text.mjs";

const show = (title, s) => console.log(`\n===== ${title}\n${s}`);
const around = (text, re, n = 3, span = 400) => {
  const out = [];
  for (const m of text.matchAll(new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g"))) {
    out.push(text.slice(Math.max(0, m.index - 80), m.index + span));
    if (out.length >= n) break;
  }
  return out.join("\n---\n") || "(no match)";
};

async function run(name, fn) {
  try {
    await fn();
  } catch (e) {
    show(name, `ERROR ${e.message}`);
  }
}

await run("product updates", async () => {
  const html = await getText("https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates");
  show("product updates text", around(plain(html), /Platform:?\s*4\.18/i, 3, 600));
  show("product updates html", around(html, /Platform:?\s*(<[^>]+>\s*)*4\.18/i, 2, 900));
});
await run("mde whats new", async () => {
  const html = await getText("https://learn.microsoft.com/en-us/defender-endpoint/whats-new-in-microsoft-defender-endpoint");
  show("mde headings", [...html.matchAll(/<h([23])[^>]*>([\s\S]*?)<\/h\1>/gi)].slice(0, 15).map((m) => `h${m[1]} ${plain(m[2])}`).join("\n"));
  const at = html.search(/<h2[^>]*>[^<]*20\d\d/i);
  show("mde first month html", at >= 0 ? html.slice(at, at + 1500) : "(no month h2)");
});
await run("msrc", async () => {
  const q = new URLSearchParams({ $filter: "releaseNumber eq '2026-Nov'", $top: "2", $count: "true" });
  const j = await getJson(`https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?${q}`);
  show("msrc vulnerability", JSON.stringify({ count: j["@odata.count"], next: j["@odata.nextLink"], keys: Object.keys(j.value?.[0] || {}), first: j.value?.[0] }, null, 1).slice(0, 2500));
  const r = await getJson("https://api.msrc.microsoft.com/cvrf/v3.0/updates");
  show("cvrf updates", JSON.stringify((r.value || []).slice(-2)));
});
