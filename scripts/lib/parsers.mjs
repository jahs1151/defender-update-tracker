// Pure parsers: HTML/JSON/XML in, plain objects out. Tested against fixtures in test/fixtures.
import { plain, tag, matchAfter, slug, toIso, osTags } from "./text.mjs";
import { nonWindowsTitle } from "./platform.mjs";
import { parseUsClock, versionMonth } from "../../site/assets/time.js";
export { versionMonth };

const V4 = /\d+\.\d+\.\d+\.\d+/;
const MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December";

/** Security intelligence page (wdsi/definitions → wdsi/defenderupdates). */
export function parseDefinitions(html) {
  const text = plain(html);
  // The page repeats a block like:
  // "The latest security intelligence update is: Version: 1.463.322.0 Engine Version: 1.1.26100.4
  //  Platform Version: 4.18.26100.4 Released: 11/16/2026 2:41:33 AM"
  const at = text.search(/latest security intelligence update is:?/i);
  if (at < 0) return null;
  const block = text.slice(at, at + 500);
  const securityIntelligence = /update is:?\s*(?:Version:\s*)?(\d+\.\d+\.\d+\.\d+)/i.exec(block)?.[1] ?? "";
  const engine = /Engine Version:\s*(\d+\.\d+\.\d+\.\d+)/i.exec(block)?.[1] ?? "";
  const platform = /Platform Version:\s*(\d+\.\d+\.\d+\.\d+)/i.exec(block)?.[1] ?? "";
  const releasedRaw = /Released:\s*(\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}(?::\d{2})?\s*[AP]M)/i.exec(block)?.[1] ?? "";
  // If Microsoft ever labels the clock, honour it.
  const zoneLabel = /Released:[^A-Za-z]{0,40}[AP]M\s*(UTC|GMT|PST|PDT|PT)\b/i.exec(block)?.[1] ?? "";
  if (!securityIntelligence || !engine || !platform) return null;
  return { securityIntelligence, engine, platform, releasedRaw, zoneLabel };
}

/**
 * The definitions page clock has no time zone. Decide it by comparing it with the
 * Last-Modified header (always GMT) of mpam-fe.exe for the same version.
 * Returns { zone, releasedAt, basis }.
 */
export function resolveDefinitionsClock(releasedRaw, zoneLabel, mpamLastModified, now = new Date()) {
  if (!releasedRaw) return { zone: "", releasedAt: "", basis: "The page did not publish a release time." };
  if (/UTC|GMT/i.test(zoneLabel)) {
    return { zone: "UTC", releasedAt: parseUsClock(releasedRaw, "UTC").toISOString(), basis: "The page labels its clock UTC." };
  }
  if (/P[SD]?T/i.test(zoneLabel)) {
    return { zone: "America/Los_Angeles", releasedAt: parseUsClock(releasedRaw, "America/Los_Angeles").toISOString(), basis: "The page labels its clock Pacific time." };
  }
  const utcAt = parseUsClock(releasedRaw, "UTC");
  const pacAt = parseUsClock(releasedRaw, "America/Los_Angeles");
  const slack = 5 * 60000;
  // 1. A release cannot be in the future. Read as Pacific, the clock is 7 to 8 hours later than read as UTC,
  //    so whenever the page is fetched within that window after a release, this settles it.
  if (pacAt.getTime() > now.getTime() + slack && utcAt.getTime() <= now.getTime() + slack) {
    return { zone: "UTC", releasedAt: utcAt.toISOString(), basis: "Verified this run: read as Pacific time the release would be in the future, so the page clock is UTC." };
  }
  // 2. The mpam-fe.exe Last-Modified header (GMT) for the same version, when it is close to one reading.
  const lm = mpamLastModified ? new Date(mpamLastModified) : null;
  if (lm && !Number.isNaN(lm.getTime())) {
    const gaps = [
      { zone: "UTC", at: utcAt, gap: Math.abs(lm - utcAt) },
      { zone: "America/Los_Angeles", at: pacAt, gap: Math.abs(lm - pacAt) },
    ].sort((x, y) => x.gap - y.gap);
    if (gaps[0].gap <= 60 * 60000 && gaps[1].gap > 3 * 3600000) {
      return {
        zone: gaps[0].zone,
        releasedAt: gaps[0].at.toISOString(),
        basis: `Verified this run: the clock matches the mpam-fe.exe Last-Modified header (GMT) within ${Math.round(gaps[0].gap / 60000)} min when read as ${gaps[0].zone === "UTC" ? "UTC" : "Pacific time"}.`,
      };
    }
  }
  // 3. Not provable on this run. UTC was confirmed on 16 Nov 2026 (a 2:41 AM release seen at 3:45 AM UTC).
  return {
    zone: "UTC",
    releasedAt: utcAt.toISOString(),
    basis: "Read as UTC. Not provable on this run; UTC was last confirmed on 16 Nov 2026, when a 2:41 AM release was already listed at 3:45 AM UTC.",
  };
}

/** Version parameters Microsoft puts on the final download URL. */
export function parseDownloadUrl(url) {
  const u = url instanceof URL ? url : new URL(url);
  const get = (k) => {
    for (const [key, val] of u.searchParams) if (key.toLowerCase() === k.toLowerCase()) return val;
    return "";
  };
  return { packageVersion: get("packageVersion"), engineVersion: get("engineVersion") };
}

/** Learn: "Microsoft Defender Antivirus security intelligence and product updates" monthly platform/engine list. */
export function parseProductUpdates(html) {
  const text = plain(html);
  const out = [];
  const re = new RegExp(
    `(?:(${MONTHS})-?\\s?(\\d{4}))?\\s*\\(?\\s*Platform:?\\s*(4\\.18\\.\\d+\\.\\d+)\\s*\\|?\\s*Engine:?\\s*(1\\.1\\.\\d+\\.\\d+)\\s*\\)?`,
    "gi",
  );
  let m;
  while ((m = re.exec(text))) {
    const platform = m[3];
    const engine = m[4];
    if (out.some((r) => r.platform === platform && r.engine === engine)) continue;
    const after = text.slice(m.index, m.index + 900);
    // "Released: November 10, 2026" or "Release date: March 25, 2026 (Engine) / March 25, 2026 (Platform)"
    const released = new RegExp(`Releas(?:ed|e date):\\s*((?:${MONTHS})\\s+\\d{1,2},\\s*\\d{4})`, "i").exec(after)?.[1] ?? "";
    const phase = /Support phase:\s*([A-Za-z ]+?(?:Updates|Support))/i.exec(after)?.[1]?.trim() ?? "";
    const si = /Security intelligence update version:\s*(\d+\.\d+\.\d+\.\d+)/i.exec(after)?.[1] ?? "";
    out.push({
      label: m[1] ? `${m[1]} ${m[2]}` : "",
      platform,
      engine,
      securityIntelligence: si,
      released: released ? isoDate(released) : "",
      supportPhase: phase,
    });
  }
  return out.slice(0, 8);
}

function isoDate(text) {
  const d = new Date(`${text} 12:00:00 UTC`);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
}

/** WDSI antimalware definition release notes (detection changelog). */
export function parseChangelog(html) {
  const text = plain(html);
  const version = /security intelligence update version\s+(\d+\.\d+\.\d+\.\d+)/i.exec(text)?.[1] ?? "";
  const releasedRaw = /id="releaseDate_0"[^>]*>([^<]+)/i.exec(html)?.[1]?.trim() ?? "";
  const rows = [];
  const addedAt = Math.max(0, html.search(/(?:Added|New) threat detections/i));
  const updatedRel = html.slice(addedAt).search(/Updated threat detections/i);
  const split = updatedRel >= 0 ? addedAt + updatedRel : -1;
  const grab = (chunk, change) => {
    const re = /<tr class="version_0">\s*<td>\s*<a[^>]*href="([^"]+)"[^>]*>([^<]+)<\/a>\s*<\/td>\s*<td[^>]*>([^<]+)<\/td>/gi;
    let m;
    while ((m = re.exec(chunk))) {
      rows.push({
        name: plain(m[2]),
        severity: plain(m[3]).toLowerCase(),
        change,
        url: new URL(m[1], "https://www.microsoft.com/en-us/wdsi/threats/").toString(),
      });
    }
  };
  grab(split > 0 ? html.slice(0, split) : html, "added");
  if (split > 0) grab(html.slice(split), "updated");
  const versions = [];
  for (const m of html.matchAll(/versionid=(\d+\.\d+\.\d+\.\d+)/gi)) if (!versions.includes(m[1])) versions.push(m[1]);
  for (const m of html.matchAll(/<option[^>]*>\s*(\d+\.\d+\.\d+\.\d+)\s*<\/option>/gi)) if (!versions.includes(m[1])) versions.push(m[1]);
  return { version, releasedRaw, rows, versions };
}

/** Windows release health status page: known issues table. */
export function parseReleaseHealth(html, page, os, label) {
  const issues = [];
  for (const row of html.split(/<tr[\s>]/i).slice(1)) {
    const cells = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)].map((m) => m[1]);
    if (cells.length < 4) continue;
    const bold = /<b>([\s\S]*?)<\/b>/i.exec(cells[0])?.[1] ?? "";
    const title = plain(bold || cells[0]);
    if (!title || /^summary$/i.test(title)) continue;
    const status = plain(cells[2]);
    if (!/confirmed|resolved|investigating|mitigated/i.test(status)) continue;
    const detail = plain(cells[0].replace(/<b>[\s\S]*?<\/b>/i, ""));
    const origin = plain(cells[1]);
    const updated = plain(cells[3]);
    const blob = `${title} ${detail} ${origin}`;
    const endpoint = /defender|antivirus|\bmde\b|intune|endpoint security|security intelligence|antimalware|tamper protection|bitlocker/i.test(blob);
    const hash = /href="#([^"]+)"/i.exec(cells[0])?.[1] ?? "";
    const updatedDate = /(\d{4}-\d{2}-\d{2})/.exec(updated)?.[1] ?? /(\d{4}-\d{2}-\d{2})/.exec(origin)?.[1] ?? "";
    issues.push({
      id: `${slug(label)}-${slug(title)}`,
      title,
      status,
      detail: detail.slice(0, 360),
      origin,
      updated: updatedDate,
      url: hash ? `${page}#${hash}` : page,
      os: [...os],
      scope: endpoint ? "security" : "windows",
      source: label,
    });
  }
  return issues;
}

/** RSS 2.0 or Atom feed to items. */
export function parseFeed(xml, source, limit = 30) {
  const isAtom = /<feed[\s>]/i.test(xml) && !/<rss[\s>]/i.test(xml);
  const blocks = xml.split(isAtom ? /<entry[\s>]/i : /<item[\s>]/i).slice(1, limit + 1);
  return blocks
    .map((b) => {
      const link = isAtom ? /<link[^>]*href="([^"]+)"/i.exec(b)?.[1] ?? "" : tag(b, "link") || /<link[^>]*href="([^"]+)"/i.exec(b)?.[1] || "";
      const published = isAtom ? tag(b, "published") || tag(b, "updated") : tag(b, "pubDate") || tag(b, "dc:date");
      return {
        title: plain(tag(b, "title")),
        url: plain(link),
        source,
        published: toIso(published),
        summary: plain(isAtom ? tag(b, "summary") || tag(b, "content") : tag(b, "description")).slice(0, 300),
      };
    })
    .filter((i) => i.title && /^https?:\/\//.test(i.url));
}

/** Keep news that is about Defender, Intune, or Windows endpoint security. */
export function isEndpointNews(item) {
  const t = `${item.title} ${item.summary}`;
  if (/\b(top\s+\d+|best\b|deals?\b|roundup)\b/i.test(item.title)) return false;
  const strong = /\b(microsoft defender|windows defender|defender for endpoint|defender antivirus|intune|smartscreen|bitlocker|patch tuesday|windows server 20(19|22|25)|windows 11)\b/i;
  const windowsSecurity = /\bwindows\b/i.test(item.title) && /\b(zero-day|0-day|exploit|vulnerab|patch|malware|ransom|privilege|out-of-band)\b/i.test(item.title);
  return strong.test(t) || windowsSecurity;
}

/** Intune what's new: weekly headings with h3/h4 items. Returns weeks with Windows/security items. */
export function parseIntuneWhatsNew(html, base) {
  const weeks = [];
  for (const section of html.split(/<h2[^>]*>/i).slice(1, 30)) {
    const heading = plain(section.split(/<\/h2>/i)[0] ?? "");
    if (!/week of/i.test(heading)) continue;
    const items = [];
    for (const m of section.matchAll(/<h[34][^>]*id="([^"]*)"[^>]*>([\s\S]*?)<\/h[34]>([\s\S]*?)(?=<h[234][^>]*>|$)/gi)) {
      const name = plain(m[2]);
      const summary = plain(m[3]).slice(0, 600);
      const blob = `${name} ${summary}`;
      if (/\b(android|ios|ipados|macos|aosp|chromeos|linux)\b/i.test(blob) && !/windows/i.test(blob)) continue;
      if (nonWindowsTitle(name)) continue;
      if (!/windows|defender|endpoint security|bitlocker|firewall|antivirus|compliance|attack surface|device control|epm|endpoint privilege/i.test(blob)) continue;
      items.push({ id: m[1] || slug(name), name, summary, url: `${base}#${m[1] || slug(name)}` });
    }
    // Learn sometimes splits one week into a service-release heading and a plain one: merge them.
    const date = heading.replace(/\s*\(.*$/, "").trim();
    const same = weeks.find((w) => w.week.replace(/\s*\(.*$/, "").trim() === date);
    if (same) {
      same.items.push(...items);
      if (heading.length > same.week.length) same.week = heading;
      continue;
    }
    weeks.push({ week: heading, items });
    if (weeks.length >= 8) break;
  }
  return weeks;
}

/** Intune in development: h3 items that touch Windows or security. */
export function parseIntuneInDevelopment(html, base) {
  const items = [];
  for (const section of html.split(/<h3[^>]*>/i).slice(1, 60)) {
    const head = section.split(/<\/h3>/i);
    const name = plain(head[0] ?? "");
    const summary = plain((head[1] ?? "").split(/<h[23]/i)[0] ?? "").slice(0, 500);
    const blob = `${name} ${summary}`;
    if (!name || name.length < 8) continue;
    if (/\b(android|ios|ipados|macos)\b/i.test(blob) && !/windows/i.test(blob)) continue;
    if (nonWindowsTitle(name)) continue;
    if (!/windows|defender|endpoint security|bitlocker|firewall|antivirus|compliance|endpoint privilege|\bepm\b|scope tag|agentic|policy configuration agent|security copilot/i.test(blob)) continue;
    if (items.some((i) => i.name === name)) continue;
    items.push({ id: slug(name), name, summary, url: base });
  }
  return items.slice(0, 30);
}

/** Defender for Endpoint what's new: one table per month (Type, Feature, Preview/GA, Description). */
export function parseMdeWhatsNew(html, base) {
  const items = [];
  let months = 0;
  for (const section of html.split(/<h2[^>]*>/i).slice(1)) {
    const when = plain(section.split(/<\/h2>/i)[0] ?? "");
    if (!new RegExp(`(${MONTHS})\\s+20\\d\\d`, "i").test(when)) continue;
    if (++months > 4) break;
    for (const row of section.split(/<tr[\s>]/i).slice(1)) {
      const raw = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)].map((m) => m[1]);
      if (raw.length < 4) continue;
      const [type, feature, stage, description] = raw.map(plain);
      const blob = `${type} ${feature} ${description}`;
      // Keep Windows items; drop rows only about macOS, Linux, Android or iOS.
      if (/\b(macos|linux|android|ios)\b/i.test(`${type} ${feature}`) && !/windows/i.test(blob)) continue;
      const href = /href="([^"]+)"/i.exec(raw[1])?.[1] || /href="([^"]+)"/i.exec(raw[3])?.[1] || "";
      items.push({
        id: `${slug(when)}-${slug(feature)}`,
        when,
        type,
        name: feature,
        stage: /ga/i.test(stage) && !/preview/i.test(stage) ? "GA" : /preview/i.test(stage) ? "Preview" : stage || "Update",
        text: description.slice(0, 500),
        url: href ? new URL(href, base).toString() : base,
      });
    }
  }
  return items.slice(0, 30);
}

/** Microsoft Update Catalog search results for the Sense (EDR sensor) update. */
export function parseSenseCatalog(html) {
  const rows = [];
  for (const row of html.split(/<tr[\s>]/i).slice(1)) {
    const text = plain(row);
    const version = /\b(10\.8\d{3}\.\d{5}\.\d{4})\b/.exec(text)?.[1];
    if (!version) continue;
    const date = /(\d{1,2})\/(\d{1,2})\/(\d{4})/.exec(text);
    rows.push({
      version,
      date: date ? `${date[3]}-${date[1].padStart(2, "0")}-${date[2].padStart(2, "0")}` : "",
      title: text.slice(0, 300),
      channel: /(Current Channel \((?:Broad|Staged|Preview)\)|Beta Channel)/i.exec(text)?.[1] || "",
    });
  }
  rows.sort((a, b) => b.version.localeCompare(a.version, undefined, { numeric: true }) || (a.date || "9").localeCompare(b.date || "9"));
  return rows;
}

/** CISA KEV feed filtered to Microsoft endpoint products. */
export function filterKev(json, months = 12, now = new Date()) {
  const cutoff = new Date(now);
  cutoff.setUTCMonth(cutoff.getUTCMonth() - months);
  const since = cutoff.toISOString().slice(0, 10);
  return (json.vulnerabilities || [])
    .filter((v) => /microsoft/i.test(v.vendorProject))
    .filter((v) => v.dateAdded >= since)
    .filter((v) => /windows|defender|intune|malware protection|smartscreen|bitlocker/i.test(`${v.product} ${v.vulnerabilityName}`))
    .map((v) => ({
      cve: v.cveID,
      name: v.vulnerabilityName,
      product: v.product,
      summary: v.shortDescription,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      ransomware: v.knownRansomwareCampaignUse,
      endpointSecurity: /defender|intune|malware protection/i.test(`${v.product} ${v.vulnerabilityName}`),
      os: osTags(`${v.product} ${v.vulnerabilityName} ${v.shortDescription}`),
      url: `https://msrc.microsoft.com/update-guide/vulnerability/${v.cveID}`,
    }))
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
}

/**
 * MSRC Security Update Guide summary.
 * osRows: { [osId]: affectedProduct rows for that OS in the month }
 * endpointRows: vulnerability rows whose title mentions Defender or Intune
 * endpointSeverity: { [cve]: severity } from affectedProduct
 */
export function summarizeMsrc({ month, osRows, endpointRows, endpointSeverity = {} }) {
  const perOs = {};
  const all = new Set();
  const critical = new Set();
  for (const [os, rows] of Object.entries(osRows)) {
    const cves = new Set();
    const crit = new Set();
    for (const r of rows) {
      if (!r.cveNumber) continue;
      cves.add(r.cveNumber);
      all.add(r.cveNumber);
      if (/critical/i.test(r.severity || "")) {
        crit.add(r.cveNumber);
        critical.add(r.cveNumber);
      }
    }
    perOs[os] = { total: cves.size, critical: crit.size };
  }
  const seen = new Set();
  const endpoint = [];
  for (const r of endpointRows) {
    if (!r.cveNumber || seen.has(r.cveNumber)) continue;
    if (r.isMariner) continue;
    const title = r.cveTitle || "";
    if (!/defender|intune|malware protection|endpoint manager/i.test(title)) continue;
    if (/android|\blinux\b|macos|\bios\b|for identity|cloud apps|office 365/i.test(title)) continue;
    seen.add(r.cveNumber);
    endpoint.push({
      cve: r.cveNumber,
      title,
      severity: endpointSeverity[r.cveNumber] || r.severity || "",
      score: r.baseScore || "",
      released: toIso(r.releaseDate || r.initialReleaseDate),
      url: `https://msrc.microsoft.com/update-guide/vulnerability/${r.cveNumber}`,
    });
  }
  return { month, windowsTotal: all.size, critical: critical.size, perOs, endpoint };
}

/** Offline image page: the versions Microsoft lists for the current kit. */
export function parseWimPage(html) {
  const text = plain(html);
  const pick = (label) => new RegExp(`${label}:?\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+)`, "i").exec(text)?.[1] ?? "";
  return {
    packageVersion: pick("Defender package version"),
    platform: pick("Platform version"),
    engine: pick("Engine version"),
    securityIntelligence: pick("Security intelligence version"),
  };
}

/** Words that suggest a faulty detection or a sensor problem. */
const CHATTER =
  /false[-\s]?positive|faulty (signature|update|detection|intelligence)|bad (signature|definition|update)|mass (detection|alert|quarantine)|detection storm|signature (revision|rollback)|reverted (signature|update)|security intelligence.{0,48}(issue|problem|false|revision)|SenseIR|MsSense|sense\.exe|impaired communication|no sensor data|sensor health|quarantin\w+ (legit|good|our|everything)/i;

export const isBadDetectionChatter = (text) => CHATTER.test(text || "");

function looksEnglish(text) {
  if ((text.match(/[^\u0000-\u007F]/g) || []).length >= 3) return false;
  return !/\b(nicht|und|der|die|das|eine|für|wird|sind|oder)\b/i.test(text);
}

/** Arctic Shift Reddit search rows to posts. `filter` keeps only Defender-related posts. */
export function parseRedditPosts(json, sub, filter) {
  const posts = [];
  for (const row of Array.isArray(json?.data) ? json.data : []) {
    const title = (row.title || "").trim();
    const body = row.selftext || "";
    if (!title || /\[(removed|deleted)\]/i.test(`${title} ${body}`) || row.author === "[deleted]") continue;
    if (row._meta?.removal_type || row._meta?.was_deleted_later) continue;
    const blob = `${title} ${body}`;
    if (!looksEnglish(blob)) continue;
    if (filter && !/defender|antivirus|\bmde\b|\bedr\b|device control|attack surface|\basr\b|security intelligence|mssense|senseir/i.test(blob)) continue;
    if (/\b(macos|mac os|ios|ipados|android|linux)\b/i.test(blob) && !/\b(windows|server 20)\b/i.test(blob)) continue;
    const at = row.created_utc || row.created || 0;
    posts.push({
      id: row.permalink || `${sub}-${at}`,
      community: `r/${row.subreddit || sub}`,
      title: plain(title),
      url: row.permalink ? `https://www.reddit.com${row.permalink}` : `https://www.reddit.com/r/${sub}/new/`,
      published: at ? new Date(at * 1000).toISOString() : "",
      summary: plain(body.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").replace(/[#*_`>]/g, " ")).slice(0, 280),
    });
  }
  return posts;
}

/** Qualys ThreatPROTECT index pages: Patch Tuesday review links by release month ("2026-Nov"). */
export function parseQualysIndex(html) {
  const map = {};
  for (const m of html.matchAll(/href="(https:\/\/threatprotect\.qualys\.com\/(\d{4})\/\d{2}\/\d{2}\/microsoft-patch-tuesday-([a-z]+)-\d{4}-security-update-review\/)"/gi)) {
    const key = `${m[2]}-${m[3].charAt(0).toUpperCase()}${m[3].slice(1, 3).toLowerCase()}`;
    if (!map[key]) map[key] = m[1];
  }
  return map;
}

/** QIDs listed on a Qualys Patch Tuesday review. */
export function parseQualysQids(html) {
  const text = plain(html);
  const qids = new Set();
  for (const block of text.matchAll(/qid:?\s*\[?\s*([0-9,\s]{4,})/gi)) for (const id of block[1].matchAll(/\d{4,6}/g)) qids.add(id[0]);
  return [...qids].sort((a, b) => Number(a) - Number(b));
}

/** AlienVault OTX file analysis to a compact row. */
export function parseOtxAnalysis(hash, body) {
  const analysis = body?.analysis;
  const plugins = analysis?.plugins || {};
  const info = analysis?.info?.results || {};
  const name = (r) => {
    if (!r || typeof r !== "object") return "";
    for (const k of ["detection", "threat", "signature", "malware", "result", "name"]) if (typeof r[k] === "string" && r[k].trim()) return r[k].trim();
    return "";
  };
  const defender = name(plugins.msdefender?.results);
  const other = name(plugins.clamav?.results);
  const fileType = [info.file_class, info.file_type].filter(Boolean).join(" · ");
  return { hash, analysed: Boolean(fileType || defender || other), fileType, defender, other };
}

/** Microsoft 365 roadmap API rows kept when the title is about Defender or Intune. */
export function filterRoadmap(json) {
  const rows = Array.isArray(json) ? json : json?.value || [];
  return rows
    .map((r) => ({
      id: String(r.id ?? ""),
      title: plain(r.title || ""),
      status: plain(r.status || ""),
      description: plain(r.description || "").slice(0, 400),
      release: r.publicDisclosureAvailabilityDate || r.generalAvailabilityDate || "",
      updated: toIso(r.modified || r.lastModified || ""),
    }))
    .filter((r) => r.id && !nonWindowsTitle(r.title) && /\bdefender\b|\bintune\b/i.test(r.title) && !/outlook|exchange|\bowa\b|dynamics|purview|office 365|for cloud|for identity|cloud apps/i.test(r.title))
    .map((r) => ({ ...r, url: `https://www.microsoft.com/microsoft-365/roadmap?id=${r.id}` }));
}
