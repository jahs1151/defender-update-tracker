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

/**
 * Per build, the Windows detections whose family this tracker saw for the first time in that build
 * (for "notable new detections"). index: updateFamilyIndex output. Returns { version: [names] }.
 */
export function firstSeenByBuild(builds = [], index = {}, limit = 6) {
  const out = {};
  for (const b of builds) {
    const names = [];
    const seen = new Set();
    for (const r of b.rows || []) {
      if (r.change !== "added" || /:(Android|MacOS|OSX|Linux|iOS|Unix)\w*\//i.test(r.name)) continue;
      const fam = familyOf(r.name);
      const key = compact(fam);
      if (!usableFamily(fam) || seen.has(key) || index[key]?.first !== b.version) continue;
      seen.add(key);
      names.push(r.name);
    }
    out[b.version] = names.slice(0, limit);
  }
  return out;
}

// ---------- 30-day detection index, partial family matching, KEV rows ----------

/**
 * Rolling index of every detection name in each changelog version:
 * { [version]: { releasedAt, names: [...] } }. Versions released more than keepDays ago are dropped.
 */
export function updateDetectionIndex(index = {}, builds = [], keepDays = 30, now = new Date()) {
  const next = { ...index };
  for (const b of builds) {
    if (!b?.version || !Array.isArray(b.rows)) continue;
    next[b.version] = { releasedAt: b.releasedAt || next[b.version]?.releasedAt || "", names: [...new Set(b.rows.map((r) => r.name).filter(Boolean))] };
  }
  const cutoff = new Date(now.getTime() - keepDays * 86400000).toISOString();
  for (const [v, e] of Object.entries(next)) if (e.releasedAt && e.releasedAt < cutoff) delete next[v];
  return next;
}

/**
 * A threat name and a Defender family refer to the same threat: the same family (see sameFamily), or,
 * case-insensitively, one is the other plus a malware-type word and the shorter is at least 5 letters
 * ("Remus" and "RemusStealer"). "Worm" never matches "XWorm": a match starts at the beginning of both.
 */
const TYPE_SUFFIX = /^(?:Info)?(?:Stealer|Loader|RAT|Bot|Botnet|Shell|Door|Backdoor|Locker|Crypt|Crypter|Miner|Spy|Spyware|Worm|Ware|Kit|Dropper|Downloader|Ransom|Ransomware|Wiper|Grabber|Logger|Keylogger|Banker|Implant|Agent)\d*$/i;

export function relatedFamily(threat, family) {
  if (sameFamily(threat, family)) return true;
  if (!usableFamily(threat) || !usableFamily(family)) return false;
  // The longer name must continue with a new word ("Remus|Stealer"), not the same word ("Valley|x").
  const x = String(threat).replace(/[^A-Za-z0-9]/g, "");
  const y = String(family).replace(/[^A-Za-z0-9]/g, "");
  const [short, long] = x.length <= y.length ? [x, y] : [y, x];
  // and that word must be a malware type: "AntiNOD" is not a kind of "Antino".
  const rest = long.slice(short.length);
  return short.length >= 5 && long.toLowerCase().startsWith(short.toLowerCase()) && TYPE_SUFFIX.test(rest);
}

/** Detections in the 30-day index whose family matches a threat name, newest build first. */
export function detectionsFor(index = {}, threat = "") {
  if (!usableFamily(threat) && !/^cve/i.test(threat)) return [];
  const isCve = /^CVE-\d{4}-\d{4,}$/i.test(threat);
  const out = [];
  const seen = new Set();
  for (const [version, e] of Object.entries(index).sort(([, a], [, b]) => (b.releasedAt || "").localeCompare(a.releasedAt || ""))) {
    for (const name of e.names || []) {
      if (seen.has(name)) continue;
      const hit = isCve ? compact(name).includes(compact(threat)) : usableFamily(familyOf(name)) && relatedFamily(threat, familyOf(name));
      if (!hit) continue;
      seen.add(name);
      out.push({ name, version, releasedAt: e.releasedAt || "" });
    }
  }
  return out;
}

/**
 * The encyclopedia result page for a "Type:Platform/Family" query. Microsoft's search answers bare
 * names with "No results found for: ***", so it is queried with a full detection prefix, and the
 * count is the "N entries found" line. Returns { answered, count, names } (names filtered by relatedFamily).
 */
export function parseEncyclopediaResults(html = "", threat = "") {
  const text = String(html).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
  const m = /(\d[\d,]*)\s+entries found/i.exec(text);
  const all = [...new Set(text.match(/\b[A-Z][A-Za-z]+:[A-Za-z0-9]+\/[A-Za-z0-9_.!-]{3,80}/g) || [])];
  const names = all.filter((n) => (/^CVE-/i.test(threat) ? compact(n).includes(compact(threat)) : relatedFamily(threat, familyOf(n))));
  return { answered: Boolean(m), count: m ? Number(m[1].replace(/,/g, "")) : 0, names: names.slice(0, 6) };
}

/**
 * One coverage row per threat name, from vendor research and news headlines.
 *  Yes:      a matching detection is in the 30-day changelog index or the encyclopedia.
 *  Unclear:  the encyclopedia answered and has no matching entry, and the index has none.
 *  Lookup failed, retrying: the encyclopedia did not answer; the next run tries again.
 * lookups: { key: { answered, names, checkedAt, failed } }, keyed by compact(name).
 */
export function coverageRows(items = [], detIndex = {}, lookups = {}, now = new Date()) {
  const rows = [];
  const seen = new Set();
  for (const p of items) {
    for (const name of p.names || threatNamesIn(p.title, p.summary)) {
      const key = `${compact(name)}|${p.url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const hits = detectionsFor(detIndex, name);
      const look = lookups[compact(name)];
      let coverage;
      let basis;
      let detections = [];
      if (hits.length) {
        coverage = "Yes";
        detections = hits.slice(0, 4).map((h) => h.name);
        basis = `In Defender's detection changelog: ${hits[0].name} in security intelligence ${hits[0].version}${hits.length > 1 ? ` and ${hits.length - 1} more in the last 30 days` : ""}.`;
      } else if (look?.names?.length) {
        coverage = "Yes";
        detections = look.names.slice(0, 4);
        basis = "Named in Microsoft's malware encyclopedia.";
      } else if (look?.answered) {
        coverage = "Unclear";
        basis = `Microsoft's malware encyclopedia answered with no entry for this family, and the last 30 days of the changelog have none. Defender may still detect it under another name.`;
      } else {
        coverage = "Lookup failed, retrying";
        basis = look?.error ? `The encyclopedia lookup failed (${look.error}). The next refresh tries again.` : "The encyclopedia has not been asked yet. The next refresh tries again.";
      }
      rows.push({ threat: name, vendor: p.source, kind: p.kind || "vendor", title: p.title, url: p.url, published: p.published || "", coverage, detections, basis, checkedAt: look?.checkedAt || now.toISOString() });
    }
  }
  return rows;
}

/** One row per CVE added to CISA KEV in the last `days` days, with any Defender detection that names it. */
export function kevRows(recent = [], detIndex = {}, lookups = {}, { days = 14, now = new Date() } = {}) {
  const since = new Date(now.getTime() - days * 86400000).toISOString().slice(0, 10);
  return recent
    .filter((v) => (v.dateAdded || "") >= since)
    .map((v) => {
      const hits = detectionsFor(detIndex, v.cve).map((h) => h.name);
      const enc = lookups[compact(v.cve)]?.names || [];
      const detections = [...new Set([...hits, ...enc])].slice(0, 4);
      return {
        cve: v.cve,
        vendor: v.vendor || "",
        product: v.product || "",
        name: v.name || "",
        dateAdded: v.dateAdded || "",
        dueDate: v.dueDate || "",
        ransomware: v.ransomware || "",
        url: `https://nvd.nist.gov/vuln/detail/${v.cve}`,
        detections,
        coverage: detections.length ? "Detection found" : "No public MDE detection found",
        checkedAt: lookups[compact(v.cve)]?.checkedAt || now.toISOString(),
      };
    })
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || a.cve.localeCompare(b.cve));
}
