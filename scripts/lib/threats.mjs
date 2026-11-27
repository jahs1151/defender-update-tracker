// Threat names from news and vendor research, matched against Defender detection names.
// Pure functions only, covered by test/threats.test.mjs.
//
// False matches are the main risk, so matching is deliberately narrow:
//  - a threat name must look like a proper malware or tool name (see threatNamesIn),
//  - it must equal a Defender detection family exactly (letters and digits only, case-insensitive),
//  - generic Defender families (Wacatac, Agent, Phish ...) and everyday words never count.
// Anything else is "Unclear", never "Yes".

/** Defender families that are heuristics or generic buckets, not a named threat. */
const GENERIC_FAMILIES = new Set(
  [
    "agent", "wacatac", "sabsik", "malgent", "casdet", "kryptik", "phonzy", "tiggre", "vigorf", "znyonm", "zpevdo", "ulise", "leonem",
    "generic", "genmal", "bearfoos", "skeeyah", "occamy", "fuery", "fuerboos", "dorv", "glupteba", "ml", "mlr", "mal", "suspicious",
    "fakelogin", "phish", "phishing", "script", "obfuse", "obfuscator", "multiverze", "crack", "keygen", "hacktool", "presenoker",
    "cobaltstrike", "meterpreter", "powershell", "python", "nodejs", "javascript", "macro", "downloader", "dropper", "injector",
    "loader", "stealer", "backdoor", "trojan", "ransom", "ransomware", "malware", "exploit", "virus", "worm", "rootkit", "miner",
    "coinminer", "bitcoinminer", "adware", "spyware", "keylogger", "banker", "infostealer", "remoteaccess", "rat", "shellcode",
    "wintrojan", "sonbokli", "znyonm", "lazy", "blackmoon", "nemucod", "smalldoor", "winlnk", "lnkrun", "autorun",
  ],
);

/** Words that look like names in a headline but are not threats. */
const NOT_THREATS = new Set(
  [
    "microsoft", "windows", "defender", "google", "apple", "android", "linux", "macos", "chrome", "firefox", "edge", "office", "outlook",
    "exchange", "sharepoint", "azure", "entra", "intune", "teams", "github", "gitlab", "openai", "chatgpt", "claude", "gemini", "copilot",
    "crowdstrike", "sentinelone", "sophos", "bitdefender", "eset", "trend", "micro", "unit", "palo", "alto", "networks", "kaspersky",
    "symantec", "broadcom", "norton", "mandiant", "fortinet", "fortiguard", "cisco", "talos", "checkpoint", "proofpoint", "huntress",
    "research", "researchers", "security", "threat", "threats", "report", "update", "patch", "critical", "new", "latest", "first", "zero",
    "attack", "attacks", "attackers", "hackers", "campaign", "campaigns", "malware", "ransomware", "stealer", "loader", "backdoor",
    "botnet", "phishing", "exploit", "vulnerability", "flaw", "flaws", "this", "that", "these", "their", "how", "why", "what", "when",
    "week", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "january", "february", "march", "april",
    "may", "june", "july", "august", "september", "october", "november", "december", "north", "korea", "korean", "china", "chinese",
    "russia", "russian", "iran", "iranian", "ukraine", "european", "america", "american", "the", "and", "with", "from", "into",
    "nuget", "npm", "pypi", "docker", "kubernetes", "wordpress", "drupal", "oracle", "vmware", "citrix", "ivanti", "juniper", "sonicwall",
    "salesforce", "okta", "zoom", "slack", "telegram", "discord", "whatsapp", "signal", "youtube", "tiktok", "facebook", "instagram",
    "amazon", "aws", "cloudflare", "akamai", "adobe", "java", "python", "powershell", "javascript", "rust", "golang", "dotnet",
    "inside", "behind", "under", "inception", "spread", "spreads", "spreading", "deliver", "delivers", "delivery", "distribute",
    "deploy", "deploys", "deploying", "using", "uses", "target", "targets", "targeting", "malicious", "fake", "mobile", "cloud",
    "custom", "novel", "stealthy", "sophisticated", "dangerous", "evolving", "multiple", "several", "another", "other", "operation", "group", "actor", "actors", "gang", "apt", "rce", "cve",
  ],
);

// Threat words match in any case ("Remus Stealer", "XWorm variant"); the name before them must still be capitalised.
const anyCase = (words) => words.replace(/[a-z]/gi, (c) => `[${c.toLowerCase()}${c.toUpperCase()}]`);
const THREAT_WORD = anyCase(
  "(?:malware|ransomware|stealer|infostealer|info-stealer|loader|backdoor|botnet|trojan|RAT|remote access trojan|wiper|rootkit|dropper|downloader|implant|spyware|worm|miner|cryptominer|keylogger|banker|webshell|web shell|framework|toolkit|variant|family|payload)",
);
const NAME = "([A-Z][A-Za-z0-9]{3,24}(?:[-_.][A-Za-z0-9]{2,12})?)";
const BEFORE = new RegExp(`\\b${NAME}\\s+${THREAT_WORD}\\b`, "g");
const DUBBED = new RegExp(`\\b(?:dubbed|called|named|codenamed|tracked as|known as)\\s+["“']?${NAME}`, "g");
const AFTER = new RegExp(`\\b${THREAT_WORD}\\s+(?:dubbed|called|named)?\\s*["“']?${NAME}`, "g");

const THREAT_IN_TITLE = new RegExp(`\\b${THREAT_WORD}s?\\b`, "i");
const VULN_IN_TITLE = /\b(?:flaws?|vulnerabilit\w+|CVE-\d|patch\w*|zero-day|RCE|bug|advisory)\b/i;
const MALWARE_SUFFIX = /(?:RAT|Shell|Stealer|Loader|Locker|Bot|Worm|Door|Miner|Spy|Crypt|Ware|Kit)\d*$/;

/** "Trojan:Win32/ValleyRAT.PAHY!MTB" -> "ValleyRAT". */
export function familyOf(detection = "") {
  const tail = String(detection).split("/").pop() || "";
  return (tail.split("!")[0] || "").split(".")[0] || "";
}

/** Letters and digits only, lower case. */
export const compact = (value = "") => String(value).toLowerCase().replace(/[^a-z0-9]/g, "");

/** A family name worth matching against news: long enough, not generic, not an everyday word. */
export function usableFamily(family = "") {
  const c = compact(family);
  return c.length >= 5 && !GENERIC_FAMILIES.has(c) && !NOT_THREATS.has(c) && !/^(?:gen|ml|mal)\d*$/.test(c) && !/^[a-z]{1,3}\d+$/.test(c);
}

/** Most longer words capitalised: a Title Case headline. */
function titleCase(text = "") {
  const words = text.split(/\s+/).filter((w) => /^[A-Za-z]{4,}/.test(w));
  return words.length >= 3 && words.filter((w) => /^[A-Z]/.test(w)).length / words.length >= 0.6;
}

/** Has an internal capital or a digit, the way malware names are usually written (XWorm, KuboShell, Lumma2). */
const distinctive = (name) => /[a-z][A-Z]|[A-Za-z]\d|^[A-Z0-9]{5,}$/.test(name);

/**
 * Proper threat names in a headline and summary. Returns [] when nothing reads as a name,
 * rather than guessing from ordinary capitalised words.
 */
export function threatNamesIn(title = "", summary = "") {
  const out = new Map();
  const add = (raw, strong) => {
    const name = String(raw || "").replace(/[.,;:'"”’]+$/, "").replace(/['’]s$/, "");
    const key = compact(name);
    if (key.length < 5 || NOT_THREATS.has(key) || GENERIC_FAMILIES.has(key) || /^\d+$/.test(key) || /^cve\d/.test(key)) return;
    if (!strong && !distinctive(name)) return;
    if (!out.has(key)) out.set(key, name);
  };
  for (const text of [title, summary]) {
    // In a Title Case headline every word is capitalised ("Spread Malware"), so there a word next to
    // "malware" counts only when it also looks like a name. In sentence case ("the Remus stealer") it counts.
    const strong = !titleCase(text);
    for (const m of text.matchAll(DUBBED)) add(m[1], true);
    for (const m of text.matchAll(BEFORE)) add(m[1], strong);
    for (const m of text.matchAll(AFTER)) add(m[1], strong);
  }
  // CamelCase or digit-bearing words in the headline (ValleyRAT, Node2Shell). Product names are written
  // the same way (GeoServer, WebClient), so such a word counts only when it ends like a malware name, or
  // the headline is about malware and not about a vulnerability.
  const malwareHeadline = THREAT_IN_TITLE.test(title) && !VULN_IN_TITLE.test(title);
  for (const m of title.matchAll(/\b([A-Z][A-Za-z0-9]{4,24})\b/g)) {
    if (distinctive(m[1]) && (MALWARE_SUFFIX.test(m[1]) || malwareHeadline)) add(m[1], false);
  }
  return [...out.values()].slice(0, 4);
}

/** Two names refer to the same family: equal when compacted, allowing a trailing "rat" on either side (ValleyRAT, Valley). */
export function sameFamily(a, b) {
  const x = compact(a);
  const y = compact(b);
  if (!x || !y) return false;
  if (x === y) return true;
  const strip = (v) => v.replace(/rat$/, "");
  return strip(x).length >= 5 && strip(x) === strip(y);
}

/**
 * Rolling index of Defender detection families seen in the changelog:
 * { familyKey: { family, first, firstAt, last, lastAt, names: [up to 3 example detection names] } }.
 * builds: [{ version, releasedAt, rows: [{ name, change }] }], oldest or newest first.
 */
export function updateFamilyIndex(index = {}, builds = [], keepDays = 120, now = new Date()) {
  const next = { ...index };
  for (const b of builds) {
    for (const r of b.rows || []) {
      const family = familyOf(r.name);
      if (!usableFamily(family)) continue;
      const key = compact(family);
      const at = b.releasedAt || now.toISOString();
      const cur = next[key] ? { ...next[key], names: [...next[key].names] } : { family, first: b.version, firstAt: at, last: b.version, lastAt: at, names: [] };
      if ((at || "") < (cur.firstAt || "9")) Object.assign(cur, { first: b.version, firstAt: at });
      if ((at || "") > (cur.lastAt || "")) Object.assign(cur, { last: b.version, lastAt: at });
      if (!cur.names.includes(r.name) && cur.names.length < 3) cur.names.push(r.name);
      next[key] = cur;
    }
  }
  const cutoff = new Date(now.getTime() - keepDays * 86400000).toISOString();
  for (const [k, v] of Object.entries(next)) if ((v.lastAt || "") < cutoff) delete next[k];
  return next;
}

function findFamily(index, name) {
  const direct = index[compact(name)];
  if (direct) return direct;
  const stripped = compact(name).replace(/rat$/, "");
  return stripped.length >= 5 ? index[stripped] || index[`${stripped}rat`] || null : null;
}

/**
 * Detection alerts: a recent security intelligence build added a detection whose family is a
 * threat named in a recent story. builds newest first; stories: [{ title, summary, url, source, published }].
 */
export function detectionAlerts(builds = [], stories = [], { days = 14, now = new Date() } = {}) {
  const since = new Date(now.getTime() - days * 86400000).toISOString();
  const named = stories
    .filter((s) => !s.published || s.published >= since)
    .flatMap((s) => (s.names || threatNamesIn(s.title, s.summary)).map((name) => ({ name, story: s })));
  const alerts = [];
  const seen = new Set();
  for (const b of builds) {
    for (const r of b.rows || []) {
      if (r.change !== "added") continue;
      const family = familyOf(r.name);
      if (!usableFamily(family)) continue;
      const hit = named.find((n) => sameFamily(n.name, family));
      if (!hit) continue;
      const key = `${b.version}|${r.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      alerts.push({
        version: b.version,
        releasedAt: b.releasedAt || "",
        detection: r.name,
        family,
        severity: r.severity || "",
        detectionUrl: r.url || "",
        threat: hit.name,
        story: { title: hit.story.title, url: hit.story.url, source: hit.story.source, published: hit.story.published || "" },
      });
    }
  }
  return alerts.slice(0, 30);
}

/** Encyclopedia search result page -> detection names that belong to the searched family. */
export function parseEncyclopediaSearch(html = "", name = "") {
  const text = String(html).replace(/<[^>]+>/g, " ");
  const names = [...new Set(text.match(/\b[A-Z][A-Za-z]+:[A-Za-z0-9]+\/[A-Za-z0-9_.!-]{3,80}/g) || [])].filter((n) => sameFamily(familyOf(n), name));
  const count = /(\d[\d,]*)\s+(?:entries|results)\s+found/i.exec(text);
  const empty = /no (?:results|entries) (?:were )?found|0\s+(?:entries|results)\s+found/i.test(text);
  return { names: names.slice(0, 4), answered: Boolean(count) || empty || names.length > 0, empty: empty && names.length === 0 };
}

/**
 * Vendor threat coverage. One row per threat name in a vendor research post.
 *  Yes:     a Defender detection with the same family is in the changelog index or the encyclopedia.
 *  No:      the encyclopedia search answered with no entries and the index has none.
 *  Unclear: no proper threat name, the lookup failed or was not run, or the post names only a CVE or actor.
 * lookups: { familyKey: { names, answered, empty, checkedAt } } from the encyclopedia.
 */
export function vendorCoverage(posts = [], index = {}, lookups = {}) {
  const rows = [];
  const seen = new Set();
  for (const p of posts) {
    const names = p.names || threatNamesIn(p.title, p.summary);
    if (!names.length) continue;
    for (const name of names) {
      const key = `${compact(name)}|${p.url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const fam = findFamily(index, name);
      const look = lookups[compact(name)];
      let coverage = "Unclear";
      let detections = [];
      let basis = "No Defender detection with this exact family name was seen, and the encyclopedia lookup did not run or did not answer.";
      if (fam) {
        coverage = "Yes";
        detections = fam.names;
        basis = `Defender detection family ${fam.family} first seen in security intelligence ${fam.first} (in this tracker's changelog history).`;
      } else if (look?.names?.length) {
        coverage = "Yes";
        detections = look.names;
        basis = "Named in Microsoft's malware encyclopedia.";
      } else if (look?.answered && look.empty) {
        coverage = "No";
        basis = "Microsoft's malware encyclopedia has no entry with this family name, and the recent changelog has none. Defender may still detect it under another name.";
      } else if (look?.answered) {
        basis = "The encyclopedia answered, but no entry carries exactly this family name.";
      }
      rows.push({ threat: name, vendor: p.source, title: p.title, url: p.url, published: p.published || "", coverage, detections, basis });
    }
  }
  return rows;
}
