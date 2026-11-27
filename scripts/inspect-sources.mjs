#!/usr/bin/env node
// Prints short excerpts of the live source pages to the log, for fixing parsers when
// Microsoft changes a layout. Run from Actions → "Inspect sources" → Run workflow.
import { getText } from "./lib/http.mjs";
import { plain } from "./lib/text.mjs";
import * as P from "./lib/parsers.mjs";

const show = (title, s) => console.log(`\n===== ${title}\n${s}`);
const around = (text, re, n = 3, span = 400) => {
  const out = [];
  for (const m of text.matchAll(new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g"))) {
    out.push(text.slice(Math.max(0, m.index - 80), m.index + span));
    if (out.length >= n) break;
  }
  return out.join("\n---\n") || "(no match)";
};
const BROWSER = { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "accept-language": "en-US,en;q=0.9" };

async function run(name, fn) {
  try {
    await fn();
  } catch (e) {
    show(name, `ERROR ${e.message}`);
  }
}

await run("encyclopedia query forms", async () => {
  const base = "https://www.microsoft.com/en-us/wdsi/threats/threat-search?query=";
  for (const q of ["Trojan:Win32/ValleyRAT", "Win32/ValleyRAT", "/ValleyRAT", "Trojan:ValleyRAT", "Trojan:Win32/Valley", "Backdoor:Win32/ValleyRAT", "Trojan:Win32/VinciRAT", "Backdoor:PowerShell/VinciRAT", "Trojan:Win32/KuboShell", "Trojan:Win32/GlassWormZZ", "Exploit:Win32/CVE-2024-21412", "ValleyRAT!MTB", "valleyrat"]) {
    const res = await fetch(base + encodeURIComponent(q), { headers: { ...BROWSER, accept: "text/html" } }).catch((e) => ({ status: e.message, url: "", text: async () => "" }));
    const html = await res.text();
    const t = plain(html);
    const count = /(\d[\d,]*)\s+entries found/i.exec(t)?.[1];
    const names = [...new Set(t.match(/\b[A-Z][A-Za-z]+:[A-Za-z0-9]+\/[A-Za-z0-9_.!-]{3,80}/g) || [])].slice(0, 6);
    show(`query=${q}`, `${res.status} final=${res.url} entries=${count} names=${names.join(" ")}`);
    if (q === "Trojan:Win32/ValleyRAT") {
      show("paging links", [...html.matchAll(/href="([^"]*(?:page|Page)[^"]*)"/g)].map((m) => m[1]).slice(0, 6).join("\n") || "(none)");
      show("result html", around(html, /Alert level/i, 1, 600));
    }
  }
});

await run("eSentire and Symantec feeds", async () => {
  for (const u of ["https://www.security.com/rss/v1/blogs/rss.xml/221", "https://www.esentire.com/resources/blog/rss.xml", "https://www.esentire.com/resources/blog/feed", "https://www.esentire.com/feed.xml", "https://www.esentire.com/sitemap.xml", "https://www.esentire.com/resources/blog"]) {
    const res = await fetch(u, { headers: { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", accept: "application/rss+xml,application/atom+xml,text/xml,*/*" } }).catch((e) => ({ status: e.message, url: u, text: async () => "" }));
    const body = await res.text();
    const items = (body.match(/<item[\s>]|<entry[\s>]/gi) || []).length;
    const links = [...new Set([...body.matchAll(/href="(\/(?:blog|resources\/blog)\/[^"#?]+)"/g)].map((m) => m[1]))].slice(0, 8);
    show(u, `${res.status} final=${res.url} bytes=${body.length} items=${items}${items ? ` first=${(/<title>(?:<!\[CDATA\[)?([^<\]]+)/i.exec(body.slice(body.search(/<item|<entry/i))) || [])[1] || ""}` : ""}\nlinks: ${links.join(" ")}\n${/sitemap/.test(u) ? around(body, /blog/i, 4, 160) : ""}`);
  }
});
