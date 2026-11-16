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
  show("product updates headings", [...html.matchAll(/<h([234])[^>]*>([\s\S]*?)<\/h\1>/gi)].slice(0, 25).map((m) => `h${m[1]} ${plain(m[2])}`).join("\n"));
  const sup = html.search(/<h2[^>]*>[^<]*platform and engine support/i);
  show("support section", sup >= 0 ? plain(html.slice(sup, sup + 5000)).slice(0, 2500) : "(none)");
  const pu = html.search(/<h2[^>]*>\s*Product updates/i);
  show("product updates section", pu >= 0 ? plain(html.slice(pu, pu + 4000)).slice(0, 2000) : "(none)");
  show("links", [...new Set([...html.matchAll(/href="([^"#]+)"/g)].map((m) => m[1]).filter((h) => /update|platform|release|version/i.test(h)))].slice(0, 40).join("\n"));
});
await run("definitionupdates info", async () => {
  const html = await getText("https://definitionupdates.microsoft.com/packages?action=info");
  show("info text", plain(html).slice(0, 3000));
});
await run("previous versions", async () => {
  const html = await getText("https://learn.microsoft.com/en-us/defender-endpoint/msda-updates-previous-versions-technical-upgrade-support");
  show("prev headings", [...html.matchAll(/<h([234])[^>]*>([\s\S]*?)<\/h\1>/gi)].slice(0, 12).map((m) => `h${m[1]} ${plain(m[2])}`).join("\n"));
  const at = html.search(/<h3[^>]*>/i);
  show("prev first html", at >= 0 ? html.slice(at, at + 1500) : "(none)");
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
  const q2 = new URLSearchParams({ $filter: "releaseNumber eq '2026-Nov' and isMariner eq false", $top: "1", $count: "true" });
  const j2 = await getJson(`https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?${q2}`);
  show("msrc non-mariner", String(j2["@odata.count"]));
  const q3 = new URLSearchParams({ $filter: "releaseNumber eq '2026-Nov' and severity eq 'Critical'", $top: "2", $count: "true" });
  const j3 = await getJson(`https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?${q3}`);
  show("msrc affectedProduct critical", JSON.stringify({ count: j3["@odata.count"], first: j3.value?.[0] }, null, 1).slice(0, 1800));
});
