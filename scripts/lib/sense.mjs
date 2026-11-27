// Sense (MsSense.exe, the Defender for Endpoint EDR sensor): release history from the
// Update Catalog and the KB5005292 page, and hand-seeded issues tracked through four stages.
// Pure functions only, covered by test/sense.test.mjs.
import { plain } from "./text.mjs";
import { cmpVersion } from "../../site/assets/time.js";

export const KB_URL =
  "https://support.microsoft.com/en-us/servicing/management-tools/microsoft-defender/update/microsoft-defender-for-endpoint-update-for-edr-sensor";

export const STAGES = ["Community reports", "Microsoft acknowledged", "Fix announced", "Fix published"];

const SENSE_VERSION = /\b10\.8\d{3}\.\d{5}\.\d{4,5}\b/g;
const NONE = /^(?:there are )?no known issues|^none\b|^not applicable/i;
const FIX_ANNOUNCED =
  /working on (?:a )?(?:fix|resolution)|fix (?:is|will be) (?:coming|planned|in progress|available in an upcoming|included in a future)|will be (?:fixed|resolved|addressed) in (?:a|an|the) (?:future|upcoming|next)|resolution (?:is|will be) (?:planned|coming|available in an upcoming)/i;
const FIX_PUBLISHED = /(?:fixed|resolved|addressed) in (?:sensor |sense |EDR sensor )?(?:version |build )?(10\.\d{4}\.\d{5}\.\d{4,5})/i;

/** OS family of one Update Catalog row title. */
export function catalogOs(title = "") {
  if (/Windows Server 2019\+|Server 2019 and later/i.test(title)) return "Windows Server 2019 and later";
  if (/Windows 10\/11|Windows 11|Windows 10/i.test(title)) return "Windows 10 and 11";
  if (/Server 2012 R2|Server 2016/i.test(title)) return "Windows Server 2012 R2 / 2016";
  if (/Windows 7|2008 R2/i.test(title)) return "Windows 7 / Server 2008 R2";
  return "Other";
}

/**
 * The KB5005292 support page. Returns the sensor version it names, and the text of its
 * "Known issues" and "Restart requirement" paragraphs. Missing text stays "" (never "no issues").
 */
export function parseSenseKb(html) {
  const text = plain(html);
  const version =
    /updates the (?:EDR )?sensor to version\s+(10\.\d+\.\d+\.\d+)/i.exec(text)?.[1] ||
    /(?:EDR )?sensor version\s+(10\.\d+\.\d+\.\d+)/i.exec(text)?.[1] ||
    "";
  const section = (heading, stops) => {
    const at = text.search(heading);
    if (at < 0) return "";
    let body = text.slice(at).replace(heading, "").replace(/^\s*:?\s*/, "").slice(0, 600);
    const stop = body.search(stops);
    if (stop >= 0) body = body.slice(0, stop);
    return body.trim().slice(0, 400);
  };
  const STOP = /\b(?:Restart requirement|How to (?:get|obtain|roll back|uninstall)|Update information|File information|Prerequisites|More information|References|Known issues in this update)\b/i;
  return {
    version,
    knownIssues: section(/Known issues in this update/i, STOP),
    restart: section(/Restart requirement/i, STOP),
    versions: [...new Set(text.match(SENSE_VERSION) || [])],
  };
}

/**
 * Every Sense release this tracker has seen: the releases kept from earlier runs plus each
 * version in the Update Catalog now. A release is never dropped once seen.
 * catalogRows: parseSenseCatalog output. kb: parseSenseKb output or null.
 */
export function mergeSenseReleases(previous = [], catalogRows = [], kb = null, today = new Date().toISOString().slice(0, 10)) {
  const byVersion = new Map(previous.map((r) => [r.version, { ...r, catalog: [...(r.catalog || [])] }]));
  for (const row of catalogRows) {
    const rel = byVersion.get(row.version) || { version: row.version, firstSeen: today, catalog: [], restart: "", source: "Microsoft Update Catalog" };
    const os = catalogOs(row.title);
    const entry = { os, date: row.date || "", channel: row.channel || "" };
    const at = rel.catalog.findIndex((c) => c.os === os && c.channel === entry.channel);
    if (at >= 0) rel.catalog[at] = entry;
    else rel.catalog.push(entry);
    byVersion.set(row.version, rel);
  }
  const kbVersion = kb?.version || "";
  if (kbVersion && !byVersion.has(kbVersion)) {
    byVersion.set(kbVersion, { version: kbVersion, firstSeen: today, catalog: [], restart: "", source: "KB5005292 page" });
  }
  const releases = [...byVersion.values()].sort((a, b) => cmpVersion(b.version, a.version));
  // The KB page describes one build. Its restart text belongs to that build, or to the newest when it names none.
  const target = kbVersion ? releases.find((r) => r.version === kbVersion) : releases[0];
  if (target && kb?.restart) target.restart = kb.restart;
  for (const r of releases) {
    r.os = [...new Set(r.catalog.map((c) => c.os))];
    r.rings = [...new Set(r.catalog.map((c) => c.channel).filter(Boolean))];
    const dates = r.catalog.map((c) => c.date).filter(Boolean).sort();
    r.released = dates[0] || r.released || "";
  }
  return releases;
}

/** Does a post look like it is about the Sense sensor at all? */
export function senseContext(text = "") {
  return /\bsense\b|mssense|kb5005292|\bedr sensor\b|defender for endpoint sensor|sensor health|\bmde\b.{0,40}(?:sensor|onboard|telemetry)|10\.8\d{3}\.\d{5}/i.test(text);
}

function regex(source) {
  try {
    return source ? new RegExp(source, "i") : null;
  } catch {
    return null;
  }
}

/**
 * Move each tracked issue forward through the four stages, never back.
 *  seed:      hand-kept issues from curated.json (senseIssues). `stage` there is a floor.
 *  previous:  the issues as stored on the last run (keeps reached stages and their dates).
 *  ctx:       { kb: {ok, knownIssues, version} | null, latest: newest Sense version,
 *               posts: [{title, summary, url, published, where}], knownIssues: release health rows, now }
 */
export function trackSenseIssues(seed = [], previous = [], ctx = {}) {
  const now = ctx.now ? new Date(ctx.now) : new Date();
  const today = now.toISOString().slice(0, 10);
  const since = new Date(now.getTime() - 14 * 86400000).toISOString();
  const kbText = ctx.kb?.ok ? ctx.kb.knownIssues || "" : "";
  const kbClear = Boolean(ctx.kb?.ok) && (!kbText || NONE.test(kbText));
  const prevById = new Map(previous.map((i) => [i.id, i]));
  return seed.map((s) => {
    const prev = prevById.get(s.id);
    const reached = { ...(prev?.reached || {}) };
    const reach = (stage, note, url, at = today) => {
      if (!reached[stage]) reached[stage] = { at, note, url: url || "" };
    };
    if (s.stage && STAGES.includes(s.stage)) {
      for (const st of STAGES.slice(0, STAGES.indexOf(s.stage) + 1)) reach(st, s.stageNote || "Hand-kept record.", s.links?.[0]?.url, s.firstSeen || today);
    }
    // 1. Community reports: matching posts in the last 14 days that are about the sensor.
    const community = regex(s.communityMatch);
    const posts = community
      ? (ctx.posts || [])
          .filter((p) => (p.published || "") >= since)
          .filter((p) => {
            const text = `${p.title} ${p.summary || ""}`;
            return community.test(text) && senseContext(text);
          })
          .sort((a, b) => (a.published || "").localeCompare(b.published || ""))
      : [];
    if (posts.length) reach("Community reports", `${posts.length} matching post${posts.length === 1 ? "" : "s"} in the last 14 days`, posts[0].url, (posts[0].published || today).slice(0, 10));
    // 2-4. Microsoft's own text: the KB5005292 known-issues paragraph and Windows release health.
    const msMatch = regex(s.microsoftMatch);
    const kbHit = Boolean(msMatch && kbText && !NONE.test(kbText) && msMatch.test(kbText));
    const health = msMatch ? (ctx.knownIssues || []).find((r) => msMatch.test(`${r.title} ${r.detail}`)) : null;
    if (kbHit) reach("Microsoft acknowledged", "Listed under Known issues on the KB5005292 page.", KB_URL);
    else if (health) reach("Microsoft acknowledged", `Listed on Windows release health (${health.status}).`, health.url);
    const msText = kbHit ? kbText : health ? `${health.title} ${health.detail} ${health.status}` : "";
    if (msText && FIX_ANNOUNCED.test(msText)) reach("Fix announced", "Microsoft says a fix is coming.", kbHit ? KB_URL : health?.url);
    const fixedIn = FIX_PUBLISHED.exec(msText)?.[1] || "";
    if (fixedIn) reach("Fix published", `Microsoft says it is fixed in ${fixedIn}.`, kbHit ? KB_URL : health?.url);
    else if (health && /resolved/i.test(health.status)) reach("Fix published", `Windows release health marks it ${health.status}.`, health.url);
    else if (
      reached["Microsoft acknowledged"] &&
      !kbHit &&
      kbClear &&
      s.affected &&
      ctx.latest &&
      cmpVersion(ctx.latest, s.affected) > 0
    ) {
      reach("Fix published", `Inferred: the KB5005292 page no longer lists it, and version ${ctx.latest} is newer than the affected ${s.affected}.`, KB_URL);
    }
    const stage = [...STAGES].reverse().find((st) => reached[st]) || "";
    return {
      id: s.id,
      title: s.title,
      affected: s.affected || "",
      scope: s.scope || "",
      symptom: s.symptom || "",
      workaround: s.workaround || "",
      links: s.links || [],
      firstSeen: s.firstSeen || prev?.firstSeen || today,
      stage,
      reached,
      posts: posts.slice(-5).reverse().map((p) => ({ title: p.title, url: p.url, published: p.published, where: p.where || "" })),
    };
  });
}

/** Recent posts that look like a Sense problem, whether or not an issue is tracked for them. */
export function senseSignal(posts = [], now = new Date()) {
  const since = new Date(now.getTime() - 7 * 86400000).toISOString();
  const PROBLEM = /\b(?:issue|problem|broken|fail\w*|error|crash\w*|stuck|pending|not reporting|no sensor data|impaired|inactive|high cpu|reboot|rollback|telemetry)\b/i;
  const seen = new Set();
  const out = [];
  for (const p of [...posts].sort((a, b) => (b.published || "").localeCompare(a.published || ""))) {
    const text = `${p.title} ${p.summary || ""}`;
    if ((p.published || "") < since || !senseContext(text) || !PROBLEM.test(text) || seen.has(p.url)) continue;
    seen.add(p.url);
    out.push({ title: p.title, url: p.url, published: p.published, where: p.where || "" });
  }
  return { count: out.length, posts: out.slice(0, 8) };
}
