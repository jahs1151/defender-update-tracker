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

await run("troubleshoot-sensor follow", async () => {
  for (const u of ["https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-sensor", "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-sensor"]) {
    const res = await fetch(u, { headers: { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" } });
    const html = await res.text();
    show(u, `${res.status} final=${res.url} title=${(/<title>([^<]*)/i.exec(html) || [])[1] || ""}`);
  }
});
await run("sense catalog details", async () => {
  for (const id of ["a6b341dd-63fa-461c-9e15-0e9f778f4d91", "30186f65-7777-4534-b132-7c5b8814d9cb"]) {
    const html = await getText(`https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=${id}`, { timeoutMs: 30000 });
    show(id, around(plain(html), /Last Modified|Release date|Date|KB5005292/i, 6, 200));
  }
});
await run("last-modified", async () => {
  const urls = ["https://www.microsoft.com/en-us/wdsi/definitions", "https://learn.microsoft.com/en-us/intune/whats-new/", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5005292", "https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes"];
  for (const u of urls) {
    const res = await fetch(u, { method: "HEAD" }).catch((e) => ({ status: e.message, headers: new Map() }));
    show(u, `${res.status} last-modified=${res.headers.get("last-modified")}`);
  }
});
