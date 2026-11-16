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

await run("sense catalog", async () => {
  const html = await getText("https://www.catalog.update.microsoft.com/Search.aspx?q=KB5005292", { timeoutMs: 30000 });
  show("sense rows", html.split(/<tr[\s>]/i).slice(1).map((r) => plain(r).replace(/\s+/g, " ").slice(0, 300)).filter((t) => /10\.8\d{3}/.test(t)).slice(0, 8).join("\n"));
});
await run("bleepingcomputer", async () => {
  const res = await fetch("https://www.bleepingcomputer.com/feed/", { headers: { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", accept: "application/rss+xml,*/*" } });
  show("bleeping", `${res.status} ${res.headers.get("content-type")} ${(await res.text()).slice(0, 300)}`);
});
await run("arctic intune", async () => {
  const res = await fetch("https://arctic-shift.photon-reddit.com/api/posts/search?subreddit=Intune&limit=40&sort=desc");
  show("arctic intune", `${res.status} ${(await res.text()).slice(0, 400)}`);
});
await run("intune in development", async () => {
  const html = await getText("https://learn.microsoft.com/en-us/intune/whats-new/in-development");
  show("in-dev headings", [...html.matchAll(/<h([23])[^>]*>([\s\S]*?)<\/h\1>/gi)].map((m) => `h${m[1]} ${plain(m[2])}`).join("\n"));
  show("scope tags", around(plain(html), /Scope tags support|Agentic identity/i, 2, 600));
});
await run("intune weekly", async () => {
  const html = await getText("https://learn.microsoft.com/en-us/intune/whats-new/");
  show("weekly headings", [...html.matchAll(/<h([234])[^>]*>([\s\S]*?)<\/h\1>/gi)].slice(0, 40).map((m) => `h${m[1]} ${plain(m[2])}`).join("\n"));
});
await run("troubleshoot-sensor", async () => {
  const res = await fetch("https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-sensor", { redirect: "manual" });
  show("troubleshoot-sensor", `${res.status} ${res.headers.get("location") || ""}`);
});
await run("last-modified", async () => {
  const urls = ["https://www.microsoft.com/en-us/wdsi/definitions", "https://learn.microsoft.com/en-us/intune/whats-new/", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5005292", "https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes"];
  for (const u of urls) {
    const res = await fetch(u, { method: "HEAD" }).catch((e) => ({ status: e.message, headers: new Map() }));
    show(u, `${res.status} last-modified=${res.headers.get("last-modified")}`);
  }
});
