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

await run("encyclopedia page structure", async () => {
  const res = await fetch("https://www.microsoft.com/en-us/wdsi/threats/threat-search?query=ValleyRAT", { headers: { ...BROWSER, accept: "text/html" } });
  const html = await res.text();
  show("status", `${res.status} final=${res.url} bytes=${html.length} ValleyRAT=${(html.match(/ValleyRAT/gi) || []).length}`);
  show("forms", (html.match(/<form[^>]*>/gi) || []).join("\n") || "(none)");
  show("inputs", (html.match(/<input[^>]*>/gi) || []).slice(0, 12).join("\n") || "(none)");
  const scripts = [...html.matchAll(/<script[^>]*src="([^"]+)"/gi)].map((m) => m[1]);
  show("scripts", scripts.join("\n"));
  show("api strings in html", around(html, /\/api\/|threat-?search|searchTerm|query=/i, 12, 220));
  show("results text", around(plain(html), /entries found|results found|results for/i, 4, 300));
  for (const s of scripts.filter((u) => /wdsi|threat|search|main|app|bundle/i.test(u)).slice(0, 8)) {
    const url = new URL(s, res.url).toString();
    const js = await fetch(url, { headers: BROWSER }).then((r) => r.text()).catch(() => "");
    show(`js ${url} (${js.length})`, around(js, /\/api\/[A-Za-z/]+|threat[A-Za-z]*[Ss]earch[A-Za-z]*|ThreatSearch|searchThreat/i, 10, 200));
  }
});

await run("encyclopedia candidate urls", async () => {
  const base = "https://www.microsoft.com/en-us/wdsi";
  for (const u of [
    `${base}/threats/threat-search?query=ValleyRAT`,
    `${base}/threats/threat-search?query=valleyrat&page=1`,
    `${base}/threats/threat-search?q=ValleyRAT`,
    `${base}/threats/threat-search?searchText=ValleyRAT`,
    `${base}/threats/threat-search?name=ValleyRAT`,
    `${base}/api/threats/search?query=ValleyRAT`,
    `${base}/api/threatsearch?query=ValleyRAT`,
    `${base}/threats/malware-encyclopedia-description?Name=Trojan:Win32/ValleyRAT.PAHY!MTB`,
    `${base}/threats/malware-encyclopedia-description?Name=Trojan:Win32/ValleyRAT`,
  ]) {
    const res = await fetch(u, { headers: { ...BROWSER, accept: "text/html,application/json" } }).catch((e) => ({ status: e.message, url: u, text: async () => "", headers: new Map() }));
    const body = await res.text();
    show(u, `${res.status} type=${res.headers.get?.("content-type")} final=${res.url} bytes=${body.length} ValleyRAT=${(body.match(/ValleyRAT/gi) || []).length}\n${around(plain(body), /entries found|results found|results for|ValleyRAT|Alert level|Detected by/i, 3, 220)}`);
  }
});

await run("changelog versions and VinciRAT", async () => {
  const url = "https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes";
  const p = P.parseChangelog(await getText(url, { timeoutMs: 30000 }));
  show("versions on page", `${p.versions.length}: ${p.versions.slice(0, 5).join(", ")} … ${p.versions.slice(-5).join(", ")} · rows on latest=${p.rows.length}`);
  const old = P.parseChangelog(await getText(`${url}?requestVersion=1.463.467.0`, { timeoutMs: 30000 }));
  show("1.463.467.0", `version=${old.version} released=${old.releasedRaw} rows=${old.rows.length} vinci=${old.rows.filter((r) => /vinci/i.test(r.name)).map((r) => r.name).join(", ")}`);
});

await run("new research feeds", async () => {
  const candidates = {
    eSentire: ["https://www.esentire.com/blog/rss.xml", "https://www.esentire.com/security-advisories/rss.xml", "https://www.esentire.com/rss.xml", "https://www.esentire.com/blog"],
    "AhnLab ASEC": ["https://asec.ahnlab.com/en/feed/", "https://asec.ahnlab.com/en/rss/"],
    watchTowr: ["https://labs.watchtowr.com/rss/", "https://labs.watchtowr.com/feed/"],
    "Check Point Research": ["https://research.checkpoint.com/feed/"],
    Symantec: ["https://www.security.com/feeds/blogs/threat-intelligence", "https://www.security.com/feed/blogs/threat-intelligence", "https://symantec-enterprise-blogs.security.com/blogs/feed", "https://www.security.com/threat-intelligence"],
  };
  for (const [name, urls] of Object.entries(candidates)) {
    for (const u of urls) {
      const res = await fetch(u, { headers: { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", accept: "application/rss+xml,application/atom+xml,text/xml,*/*" } }).catch((e) => ({ status: e.message, url: u, text: async () => "" }));
      const body = await res.text();
      const items = (body.match(/<item[\s>]|<entry[\s>]/gi) || []).length;
      const feeds = [...body.matchAll(/<link[^>]+(?:rss|atom)\+xml[^>]*>/gi)].map((m) => m[0]).slice(0, 3).join(" ");
      show(`${name} ${u}`, `${res.status} final=${res.url} items=${items} ${feeds}${items ? `\nfirst: ${(/<title>(?:<!\[CDATA\[)?([^<\]]+)/i.exec(body.slice(body.search(/<item|<entry/i))) || [])[1] || ""}` : ""}`);
    }
  }
});
