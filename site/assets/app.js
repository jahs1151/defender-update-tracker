import { stamp, ago, cmpVersion, monthsBetween, versionMonthLabel } from "./time.js";

const OS = { win11: "Win 11", srv2019: "Server 2019", srv2022: "Server 2022", srv2025: "Server 2025" };
const ALL_OS = Object.keys(OS);
const TABS = ["status", "updates", "sense", "threats", "intune", "intel"];

const state = { pulse: null, catalog: null, curated: null, os: "all", tab: "status", errors: {} };

// ---------- helpers ----------
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const link = (url, text, cls = "") =>
  url && /^https?:\/\//.test(url) ? `<a class="${cls}" href="${esc(url)}" target="_blank" rel="noopener">${esc(text)}</a>` : esc(text);
const source = (url, text = "Source") => (url ? `<div>${link(url, `${text} ↗`, "src")}</div>` : "");
const na = (text = "Not available yet") => `<span class="na">${esc(text)}</span>`;
const pill = (text, tone = "") => `<span class="pill ${tone}">${esc(text)}</span>`;
const osOk = (list) => state.os === "all" || !list || !list.length || list.includes(state.os);
const osPills = (list) => (list && list.length && list.length < ALL_OS.length ? list.map((o) => pill(OS[o] || o)).join(" ") : "");
const sec = (key) => state.pulse?.sections?.[key] || null;
const CHATTER =
  /false[-\s]?positive|faulty (signature|update|detection|intelligence)|bad (signature|definition|update)|mass (detection|alert|quarantine)|detection storm|signature (revision|rollback)|reverted (signature|update)|security intelligence.{0,48}(issue|problem|false|revision)|SenseIR|MsSense|sense\.exe|impaired communication|no sensor data|sensor health|quarantin\w+ (legit|good|our|everything)/i;
const CONTROLS = /\busb\b|removable|device control|firewall|attack surface|\basr\b|bitlocker/i;
const OOB_RE = /out-of-band|emergency (update|patch|fix)|zero-day|0-day|actively exploited/i;
/** News stories whose one home is the Out-of-band and zero-day section. */
function oobStories() {
  const since = state.pulse?.patch?.last || "";
  return (data("news")?.items || []).filter((n) => OOB_RE.test(n.title) && (!since || (n.published || "") >= since.slice(0, 10)));
}
const slugId = (u) => String(u || "").replace(/^https?:\/\/[^/]+\//, "").replace(/[^a-z0-9]+/gi, "-").slice(0, 60);
// James's chosen link (round 6). On 16 Nov 2026 this URL returned 404 from GitHub's runners; the live pages are listed after it.
const SENSOR_TROUBLESHOOT = { url: "https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-sensor", title: "Sensor troubleshooting" };
const daysOld = (iso) => (iso ? (Date.now() - Date.parse(iso)) / 86400000 : Infinity);
const size = (b) => (!b ? "" : b >= 1048576 ? `${(b / 1048576).toFixed(b >= 10485760 ? 0 : 1)} MB` : `${Math.round(b / 1024)} KB`);
const data = (key) => sec(key)?.data || null;

function checked(key, detailOverride) {
  const base = sec(key);
  const s = base && detailOverride ? { ...base, detail: detailOverride } : base;
  if (!s) return "";
  const when = s.lastOkAt ? `Last good data ${ago(s.lastOkAt)}` : "No data yet";
  const tone = s.ok ? "" : s.stale ? "warn" : "bad";
  const status = s.ok ? "" : ` ${pill(s.stale ? "Stale" : "Unavailable", tone)}`;
  return `<span class="meta" title="${esc(s.detail)}">Checked ${esc(ago(s.checkedAt))} · ${esc(when)}${status}</span>`;
}

function section(id, title, body, key, detail) {
  return `<section class="section" id="${id}" aria-labelledby="${id}-h">
    <div class="section-head"><h2 id="${id}-h">${esc(title)}</h2>${key ? checked(key, detail) : ""}</div>
    ${body}
  </section>`;
}

function sectionError(key, what) {
  const s = sec(key);
  if (s?.data) return "";
  const detail = s ? s.detail : "This source is missing from the data file.";
  return `<div class="notice">${esc(what)} could not be read on the last check. ${esc(detail)} The next scheduled run tries again.</div>`;
}

const pref = {
  get(key, fallback) {
    try {
      const v = localStorage.getItem(`dut:${key}`);
      return v == null ? fallback : JSON.parse(v);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(`dut:${key}`, JSON.stringify(value));
    } catch {
      /* private mode */
    }
  },
};

// ---------- loading ----------
async function getJson(path, timeoutMs = 15000, retries = 2) {
  let last;
  for (let i = 0; i <= retries; i += 1) {
    try {
      const res = await fetch(`${path}?t=${Math.floor(Date.now() / 60000)}`, { signal: AbortSignal.timeout(timeoutMs), cache: "no-cache" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      last = e;
      if (i < retries) await new Promise((r) => setTimeout(r, 800 * 2 ** i));
    }
  }
  throw last;
}

async function load() {
  const [pulse, catalog, curated, links] = await Promise.allSettled([
    getJson("data/pulse.json"),
    getJson("data/features.json"),
    getJson("data/curated.json"),
    getJson("data/link-report.json", 8000, 0),
  ]);
  state.failedUrls = new Set(links.status === "fulfilled" ? links.value.failedUrls || [] : []);
  state.pulse = pulse.status === "fulfilled" ? pulse.value : null;
  state.catalog = catalog.status === "fulfilled" ? catalog.value : null;
  state.curated = curated.status === "fulfilled" ? curated.value : null;
  if (!state.pulse) state.errors.pulse = String(pulse.reason?.message || pulse.reason);
  render();
}

// ---------- header ----------
function renderAsOf() {
  const el = document.getElementById("asof");
  const p = state.pulse;
  if (!p) {
    el.textContent = "Data file did not load. Reload to try again.";
    el.classList.add("stale");
    return;
  }
  const age = (Date.now() - Date.parse(p.checkedAt)) / 3600000;
  el.innerHTML = `Data as of ${esc(stamp(p.checkedAt))}${p.seed ? " · seed snapshot" : ""}`;
  el.classList.toggle("stale", age > 3 || Boolean(p.seed));
  el.title = age > 3 ? "The scheduled refresh has not run for more than 3 hours." : "";
}

// ---------- Status tab ----------
function versionCard(label, value, when, sourceUrl, extra = "") {
  return `<div class="card">
    <div class="kpi-label">${esc(label)}</div>
    <div class="kpi">${value ? esc(value) : na()}</div>
    ${when ? `<div class="when">${esc(when)}</div>` : ""}
    ${extra}
    ${source(sourceUrl)}
  </div>`;
}

function senseInfo() {
  const sd = data("sense");
  const live = sd?.latest;
  if (live) {
    const builds = sd.builds?.length ? sd.builds : [{ os: "", date: live.date, channel: live.channel }];
    const channel = live.channel || builds.find((b) => b.channel)?.channel || "";
    const catalog = builds.map((b) => `${b.os ? `${b.os}: ` : ""}${b.date ? stamp(b.date).replace(/\s*\(date only\)/, "") : "date not published"}`).join(" · ");
    const f = state.curated?.senseFallback;
    const release = f?.version === live.version && f.date ? senseReleaseStamp(f.date) : "";
    const when = release ? `Released ${release}` : catalog;
    const note = release ? `Release date from the hand-kept record. Microsoft's Update Catalog lists this build as last modified ${catalog} and publishes no time of day.` : "Microsoft Update Catalog (KB5005292). The catalog publishes a date per OS family, not a time.";
    return { version: live.version, when, channel, note, url: sd.url };
  }
  const f = state.curated?.senseFallback;
  if (f) return { version: f.version, when: stamp(f.date), channel: f.channel, note: f.source, url: f.url };
  return { version: "", when: "", channel: "", note: "", url: "" };
}

/** "11 Nov 2026 UTC · 11 Nov 2026 CST": a date with no published time, shown in both zones without inventing a time. */
function senseReleaseStamp(date) {
  const d = new Date(`${date}T12:00:00Z`);
  const day = d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
  const zone = d.toLocaleString("en-US", { timeZone: "America/Chicago", timeZoneName: "short" }).split(" ").pop();
  return `${day} UTC · ${day} ${zone} (time of day not published)`;
}

/** One release time for the current security intelligence: the changelog's, when it lists the same build. */
function siRelease() {
  const intel = data("intelligence");
  const cl = data("changelog");
  if (cl?.releasedAt && cl.version === intel?.securityIntelligence) return { at: cl.releasedAt, basis: "changelog" };
  if (intel?.releasedAt) return { at: intel.releasedAt, basis: "definitions" };
  return { at: "", basis: "" };
}

function renderChanges() {
  const p = state.pulse;
  if (p.seed) {
    return `<div class="notice info">This is the seed snapshot carried over from the previous site. The first scheduled refresh replaces it with live data and starts tracking changes.</div>`;
  }
  if (!p.changes?.length) return `<div class="card"><p>No version or content changes since ${esc(stamp(p.contentChangedAt))}.</p></div>`;
  const rows = p.changes
    .map((c) => {
      const body =
        c.kind === "changed"
          ? `<code>${esc(c.from)}</code> → <code>${esc(c.to)}</code>`
          : c.kind === "added"
            ? `${pill("New", "ok")} ${esc(c.to)}`
            : `${pill("Gone")} ${esc(c.from)}`;
      return `<li><span class="row-title">${esc(c.field)}</span> ${body}</li>`;
    })
    .join("");
  return `<div class="card"><p class="meta">Detected ${esc(stamp(p.contentChangedAt))} · <a href="feed.xml">RSS feed of changes</a></p><ul class="list changes">${rows}</ul></div>`;
}

function renderStatus() {
  const intel = data("intelligence");
  const pkgs = Array.isArray(data("packages")) ? data("packages") : [];
  const mpam = pkgs.find((p) => p.id === "mpam-fe");
  const plat = pkgs.find((p) => p.id === "updateplatform");
  const sense = senseInfo();
  const releases = data("productUpdates")?.rows || [];
  const platRelease = releases.find((r) => r.platform === intel?.platform);
  const engRelease = releases.find((r) => r.engine === intel?.engine);

  const si = siRelease();
  const siWhen = si.at ? `Released ${stamp(si.at)}` : mpam?.lastModified ? `Package dated ${stamp(mpam.lastModified)}` : "";
  const pageTime = intel?.releasedAt && si.basis === "changelog" && intel.releasedAt !== si.at ? ` The definitions page shows ${stamp(intel.releasedAt).split(" · ")[0]} for the same build; this site uses the changelog time everywhere.` : "";
  const clockNote = intel?.clockBasis ? `<p class="meta" style="margin-top:6px">${esc(intel.clockBasis + pageTime)}</p>` : "";
  const engMonth = versionMonthLabel(intel?.engine || "");
  const engineWhen = engRelease?.released
    ? `Monthly release ${stamp(engRelease.released)}`
    : si.at
      ? `Delivered with security intelligence released ${stamp(si.at)}`
      : "";
  const engineNote = `<p class="meta" style="margin-top:6px">${engMonth ? `Build month ${esc(engMonth)} (from the version number). ` : ""}The engine ships inside the security intelligence package, so its time is that package's release time.</p>`;
  const platWhen = platRelease?.released ? `Monthly release ${stamp(platRelease.released)}` : plat?.lastModified ? `Package dated ${stamp(plat.lastModified)}` : "";

  const cards = `<div class="grid">
    ${versionCard("Security intelligence", intel?.securityIntelligence || mpam?.version, siWhen, intel?.url || "https://www.microsoft.com/en-us/wdsi/definitions", clockNote)}
    ${versionCard("Engine", intel?.engine || mpam?.engine, engineWhen, intel?.url, engineNote)}
    ${versionCard("Platform", intel?.platform || plat?.version, platWhen, "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates")}
    ${versionCard("Sense (MsSense.exe)", sense.version, sense.when, sense.url, `${sense.channel ? `<div class="when">Ring: ${esc(sense.channel)}</div>` : ""}${sense.note ? `<p class="meta" style="margin-top:6px">${esc(sense.note)}</p>` : ""}<div><a class="src" href="#sense-releases">Release history and issues</a></div>`)}
  </div>`;

  const wimBehind = (p) => p.id === "wim" && p.version && mpam?.version && cmpVersion(p.version, mpam.version) < 0;
  const pkgRows = pkgs
    .map(
      (p) => `<tr>
        <td><div class="row-title">${esc(p.name)}</div><div class="meta">${esc(p.file)}${p.kb ? ` · ${esc(p.kb)}` : ""}</div>${wimBehind(p) ? `<div style="margin-top:4px">${pill("WIM is behind — use mpam-fe.exe", "warn")}</div>` : ""}</td>
        <td class="mono">${p.version ? esc(p.version) : na()}${p.engine ? `<div class="meta">engine ${esc(p.engine)}</div>` : ""}${p.id === "wim" && p.platform ? `<div class="meta" title="${esc(p.platformSource || "")}">platform ${esc(p.platform)}</div>` : ""}</td>
        <td>${p.lastModified ? esc(stamp(p.lastModified)) : na("Time not published")}${p.contents?.length ? `<div class="meta">Contains ${esc(p.contents.join(", "))}${p.contentsDate ? `, files dated ${esc(stamp(p.contentsDate))}` : ""}</div>` : ""}</td>
        <td>${esc(size(p.bytes))}</td>
        <td>${link(p.latestUrl, "Download x64")} · ${link(p.page, "Docs")}</td>
      </tr>`,
    )
    .join("");
  const packages = pkgs.length
    ? `<div class="card table-wrap"><table><thead><tr><th>Package</th><th>Version</th><th>File date (Last-Modified)</th><th>Size</th><th>Links</th></tr></thead><tbody>${pkgRows}</tbody></table>
       <p class="meta" style="margin-top:8px">mpam-fe.exe updates security intelligence and the engine, not the platform. updateplatform.exe updates only the platform. The offline image kit (WIM) is for servicing install images${(() => {
         const w = pkgs.find((p) => p.id === "wim");
         return w?.platformSource ? `. Its platform version is ${esc(w.platformSource.charAt(0).toLowerCase() + w.platformSource.slice(1))}` : "";
       })()}.</p></div>`
    : sectionError("packages", "The download packages");

  const currentPlatform = intel?.platform || plat?.version || "";
  const support = (platform) => {
    const gap = monthsBetween(currentPlatform, platform);
    if (gap == null) return "";
    if (gap <= 0) return pill("Current (N)", "ok");
    if (gap <= 2) return pill(`Supported (about N-${gap})`, "ok");
    return pill("Older than N-2", "bad");
  };
  const latestListed = releases[0];
  const lag = latestListed ? monthsBetween(currentPlatform, latestListed.platform) : null;
  const listedCurrent = releases.some((r) => r.platform === currentPlatform);
  const currentRow =
    currentPlatform && !listedCurrent
      ? `<tr><td><strong>Current build</strong> ${pill("Not on the release notes page yet", "warn")}<div class="meta">Build month ${esc(versionMonthLabel(currentPlatform) || "unknown")}</div></td><td class="mono">${esc(currentPlatform)}</td><td class="mono">${esc(intel?.engine || "")}</td><td>${plat?.lastModified ? `${esc(stamp(plat.lastModified))}<div class="meta">updateplatform.exe file date</div>` : na("Not published")}</td><td>${pill("Current (N)", "ok")}</td></tr>`
      : "";
  const relRows = currentRow + releases
    .map((r) => `<tr><td>${esc(r.label)}</td><td class="mono">${esc(r.platform)}</td><td class="mono">${esc(r.engine)}</td><td>${r.released ? esc(stamp(r.released)) : na("Not published")}</td><td>${support(r.platform)}</td></tr>`)
    .join("");
  const releaseTable = `<div class="card">
      <p>Microsoft supports the current platform and engine plus the two monthly releases before them (N-2). Older clients stop receiving security intelligence. Defender versions carry their build month (4.18.<strong>2610</strong>0.x is an October 2026 build), so this site estimates N-2 from that month code against the current platform ${currentPlatform ? `<code>${esc(currentPlatform)}</code>` : ""}.</p>
      ${lag != null && lag > 2 ? `<div class="notice">Microsoft's release-notes page currently lists releases only up to ${esc(latestListed.label)}, ${lag} months behind the current platform. Use the month-code estimate and Compare versions for recent builds.</div>` : ""}
      ${releases.length || currentRow ? `<div class="table-wrap"><table><thead><tr><th>Release notes entry</th><th>Platform</th><th>Engine</th><th>Released</th><th>Support today</th></tr></thead><tbody>${relRows}</tbody></table></div>` : sectionError("productUpdates", "The monthly release notes")}
      ${source("https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates", "Microsoft Defender Antivirus security intelligence and product updates")}
      ${source(data("productUpdates")?.url, "Monthly platform and engine release notes")}
    </div>`;

  const sources = Object.entries(state.pulse.sections)
    .map(
      ([, s]) => `<li><span class="row-title">${esc(s.label)}</span> ${s.ok ? pill("Live", "ok") : s.stale ? pill("Stale", "warn") : pill("Failed", "bad")}
        <div class="meta">${esc(s.detail)}</div>
        <div class="meta">${s.page ? `${link(s.page, "Source page ↗")} · ` : ""}Last-Modified: ${s.lastModified ? esc(stamp(s.lastModified)) : "not sent by this source"} · Checked ${esc(stamp(s.checkedAt))}</div></li>`,
    )
    .join("");
  const legend = `<div class="legend">
    <div>${pill("Live", "ok")} Read successfully on the last scheduled refresh.</div>
    <div>${pill("Stale", "warn")} The last read failed; the page shows the last good data and says how old it is.</div>
    <div>${pill("Failed", "bad")} The last read failed and there is no earlier data to show.</div>
    <div>A source that is Stale or Failed is retried at the next scheduled refresh (hourly, every 15 minutes in Patch Tuesday week). Last-Modified is the date the source's server gave for the page, when it sends one.</div>
  </div>`;

  return [
    section("changes", "What changed since the last refresh", renderChanges()),
    section("versions", "Current Defender versions", cards, "intelligence"),
    section("packages", "Download packages", packages, "packages"),
    section("monthly", "Monthly platform and engine releases (N-2)", releaseTable, "productUpdates"),
    section("compare", "Compare versions", renderCompareVersions(releases, intel)),
    section("sources", "Source health", `<div class="card"><ul class="list">${sources}</ul>${legend}</div>`),
  ].join("");
}

function renderCompareVersions(releases, intel) {
  // Only well-formed versions are ever kept; anything else saved by an older version of this page is dropped.
  // Values are kept only after someone types them (typed: true); until then SI defaults to the latest build.
  const raw = pref.get("compare", {});
  const saved = Object.fromEntries(["platform", "engine", "si"].map((k) => [k, raw?.typed && VALID_VERSION.test(String(raw?.[k] || "")) ? raw[k] : ""]));
  if (!raw?.typed && Object.keys(raw || {}).length) pref.set("compare", {});
  if (!saved.si && intel?.securityIntelligence) saved.si = intel.securityIntelligence;
  return `<div class="card">
    <p>Enter Defender versions to see how they compare with the current build (Get-MpComputerStatus shows AMProductVersion, AMEngineVersion and AntivirusSignatureVersion). Saved only in this browser.</p>
    <form class="form-grid" id="compare-form" autocomplete="off">
      <label class="field">Platform <input type="text" name="platform" inputmode="decimal" placeholder="4.18.xxxxx.x" value="${esc(saved.platform)}"></label>
      <label class="field">Engine <input type="text" name="engine" inputmode="decimal" placeholder="1.1.xxxxx.x" value="${esc(saved.engine)}"></label>
      <label class="field">Security intelligence <input type="text" name="si" inputmode="decimal" placeholder="1.4xx.xxx.0" value="${esc(saved.si)}"></label>
    </form>
    <div id="compare-out" aria-live="polite" style="margin-top:10px">${compareVerdict(saved, releases, intel)}</div>
  </div>`;
}

const VALID_VERSION = /^\d+\.\d+\.\d+\.\d+$/;
const invalid = (example) => `<span class="invalid">Not a valid version — use e.g. ${esc(example)}</span>`;

function compareVerdict(v, releases, intel) {
  const out = [];
  const rank = (value, current) => {
    if (!value) return "";
    if (!VALID_VERSION.test(value)) return invalid(current || "4.18.26100.4");
    if (!current) return pill("Current version not known yet", "warn");
    if (cmpVersion(value, current) >= 0) return pill("Matches the polled build", "ok");
    const gap = monthsBetween(current, value);
    if (gap == null) return pill("Unrecognised version format", "warn");
    if (gap <= 2) return pill(`Supported (about N-${Math.max(gap, 1)})`, "ok");
    return pill(`About ${gap} months old: older than N-2, update it`, "bad");
  };
  if (v.platform) out.push(`<li>Platform <code>${esc(v.platform)}</code> ${rank(v.platform, intel?.platform)}</li>`);
  if (v.engine) out.push(`<li>Engine <code>${esc(v.engine)}</code> ${rank(v.engine, intel?.engine)}</li>`);
  if (v.si && !VALID_VERSION.test(v.si)) out.push(`<li>Security intelligence <code>${esc(v.si)}</code> ${invalid(intel?.securityIntelligence || "1.463.322.0")}</li>`);
  else if (v.si && intel?.securityIntelligence) {
    const d = cmpVersion(intel.securityIntelligence, v.si);
    out.push(`<li>Security intelligence <code>${esc(v.si)}</code> ${d <= 0 ? pill("Matches the polled build", "ok") : pill(`Behind the current ${intel.securityIntelligence}`, "warn")}</li>`);
  }
  return out.length ? `<ul class="list">${out.join("")}</ul><p class="meta">Platform and engine support is estimated from the build month in the version number.</p>` : `<p class="meta">Enter a version to compare.</p>`;
}

// ---------- Updates tab ----------
function renderUpdates() {
  const kevAll = data("kev")?.rows || [];
  const kev = kevAll.filter((r) => osOk(r.os));
  const kevSet = new Set([...(data("kev")?.microsoftCves || []), ...kevAll.map((r) => r.cve)]);
  const cisa = (cve) => (!data("kev") ? "" : /^CVE-/.test(cve) && kevSet.has(cve) ? pill("CISA catalog", "bad") : pill("Not in the CISA catalog"));
  const ptData = data("patchTuesday");
  const p = state.pulse.patch;
  // One month picker drives the Patch Tuesday cards, the CVE tables and the Qualys QIDs.
  const q = data("qualys");
  const monthKey = (m) => Date.parse(`${m.slice(5)} 1, ${m.slice(0, 4)}`) || 0;
  const allMonths = [...new Set([...Object.keys(ptData?.months || {}), ptData?.month, ...Object.keys(q?.months || {}), q?.month].filter(Boolean))].sort((a, b) => monthKey(b) - monthKey(a)).slice(0, 3);
  const savedMonth = pref.get("ptMonth", "");
  const month = allMonths.includes(savedMonth) ? savedMonth : ptData?.month || allMonths[0];
  const pt = ptData ? ptData.months?.[month] || (ptData.month === month ? ptData : null) : null;
  const monthTabs = allMonths.length > 1 ? `<div class="seg" role="tablist" aria-label="Patch Tuesday month">${allMonths.map((m) => `<button type="button" role="tab" data-ptmonth="${esc(m)}" aria-selected="${m === month}">${esc(m)}</button>`).join("")}</div>` : "";
  // The header line follows the picked month, like the cards below it.
  const ptLine = pt ? `${month}: ${pt.windowsTotal} Windows CVEs, ${pt.critical} Critical, ${pt.endpoint.length} Defender or Intune · ${allMonths.length} months kept` : "";
  const ptBody = (ptLine ? `<p class="meta" id="pt-line">${esc(ptLine)}</p>` : "") + monthTabs + (pt
    ? `<div class="grid">
        <div class="card"><div class="kpi-label">Release</div><div class="kpi">${esc(month)}</div><div class="when">${month === ptData.month ? `Last Patch Tuesday ${esc(stamp(p.last))}. Next ${esc(stamp(p.next))}.` : "An earlier release, kept for comparison."}</div>${source(ptData.url, "Security Update Guide")}</div>
        <div class="card"><div class="kpi-label">Windows CVEs (in-scope versions)</div><div class="kpi">${esc(pt.windowsTotal)}</div><div class="when">${esc(pt.critical)} rated Critical</div></div>
        <div class="card"><div class="kpi-label">Defender or Intune CVEs</div><div class="kpi">${esc(pt.endpoint.length)}</div><div class="when">${pt.endpoint.length ? "Listed below" : "None in this release"}</div></div>
      </div>
      <div class="card table-wrap" style="margin-top:12px"><table><thead><tr><th>Operating system</th><th>CVEs</th><th>Critical</th></tr></thead><tbody>${Object.entries(pt.perOs || {})
        .sort(([a], [b]) => ALL_OS.indexOf(a) - ALL_OS.indexOf(b))
        .filter(([os]) => state.os === "all" || os === state.os)
        .map(([os, c]) => `<tr><td>${esc(OS[os] || os)}</td><td>${esc(c.total)}</td><td>${esc(c.critical)}</td></tr>`)
        .join("")}</tbody></table><p class="meta" style="margin-top:6px">Windows 11 counts 24H2 and 25H2 together. Counts include CVEs Microsoft added to the release after Patch Tuesday.</p></div>
      ${pt.endpoint.length ? `<div class="card table-wrap" style="margin-top:12px"><table><thead><tr><th>CVE</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Released</th></tr></thead><tbody>${pt.endpoint
        .map((r) => `<tr><td>${link(r.url, r.cve)} ${cisa(r.cve)}</td><td>${esc(r.title)}</td><td>${esc(r.severity)}</td><td>${esc(r.score)}</td><td>${r.released ? esc(stamp(r.released)) : na("Time not published")}</td></tr>`)
        .join("")}</tbody></table></div>` : ""}`
    : ptData
      ? `<div class="card"><p>The Security Update Guide summary for ${esc(month)} is not stored yet. It is fetched on the next scheduled refresh.</p></div>`
      : `${sectionError("patchTuesday", "The Security Update Guide")}<div class="card"><p>Last Patch Tuesday ${esc(stamp(p.last))}. Next ${esc(stamp(p.next))}.</p></div>`);

  const qPick = month;
  const qm = q ? q.months?.[qPick] || (q.month === qPick ? q : null) : null;
  const qualysBody = qm
    ? `<div class="card">
        ${monthTabs}
        <p>${esc(qm.qids.length)} Qualys QIDs detect the ${esc(qPick)} Patch Tuesday fixes. Paste the query into Qualys VMDR to find unpatched hosts.</p>
        <div class="policy"><dl class="kv"><dt>Query</dt><dd><code>${esc(qm.query)}</code><button type="button" class="btn small" data-copy="${esc(qm.query)}" data-label="Copy Qualys QQL">Copy Qualys QQL</button></dd></dl></div>
        <p class="meta" style="margin-top:8px">CVE data from the Microsoft Security Update Guide, QIDs from Qualys's public monthly review.</p>
        ${source(qm.url, `Qualys ${qPick} Patch Tuesday review`)}
      </div>`
    : `<div class="card">${monthTabs}<p class="meta">${q ? `No Qualys QIDs stored for ${esc(qPick)}.` : esc(sec("qualys")?.detail || "Not checked yet.")} Qualys usually posts its review on Patch Tuesday evening, US time.</p></div>`;

  // Hand-kept entries whose link failed the weekly check are hidden until fixed.
  const incidents = (state.curated?.incidents || []).filter((i) => !state.failedUrls?.has(i.url));
  const kevBody = `<div class="card">
    ${incidents.length ? `<h3>Defender exploits tracked by hand</h3><ul class="list" style="margin-bottom:14px">${incidents
      .map((i) => `<li><span class="row-title">${link(i.url, i.name)}</span> ${pill(i.status, i.status === "Patched" ? "ok" : "warn")} ${cisa(i.id)}<div class="meta">${esc(stamp(i.date))}</div><p>${esc(i.summary)}</p></li>`)
      .join("")}</ul>` : ""}
    <h3>CISA Known Exploited Vulnerabilities, Microsoft Windows and endpoint, last 12 months</h3>
    ${data("kev") ? `<p class="meta">Showing ${kev.length} of ${kevAll.length} entries${state.os === "all" ? "" : ` (the ${esc(OS[state.os])} filter hides ${kevAll.length - kev.length} that do not apply to it)`}. Every row here is in the CISA catalog.</p>` : ""}
    ${kev.length ? `<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Name</th><th>Added</th><th>Due</th></tr></thead><tbody>${kev
      .slice(0, 25)
      .map((r) => `<tr><td>${link(r.url, r.cve)} ${pill("CISA catalog", "bad")}${r.endpointSecurity ? ` ${pill("Defender/Intune", "bad")}` : ""}</td><td>${esc(r.name)}${r.ransomware === "Known" ? ` ${pill("Ransomware", "bad")}` : ""}</td><td>${esc(stamp(r.dateAdded))}</td><td>${r.dueDate ? esc(stamp(r.dueDate)) : ""}</td></tr>`)
      .join("")}</tbody></table></div>` : data("kev") ? `<p>No entries match this filter.</p>` : sectionError("kev", "The CISA catalog")}
    ${source(data("kev")?.url, "CISA catalog")}
  </div>`;

  const everyIssue = data("knownIssues")?.rows || [];
  const allIssues = everyIssue.filter((r) => osOk(r.os));
  const hiddenByOs = everyIssue.length - allIssues.length;
  const ISSUE_TABS = {
    all: { label: "All", test: () => true },
    endpoint: { label: "Defender and Intune", test: (r) => r.scope === "security" || /defender|intune|bitlocker|autopilot|\bmdm\b|enrol|device control|removable storage|firewall|attack surface/i.test(`${r.title} ${r.detail}`) },
    win11: { label: "Windows 11", test: (r) => r.os.includes("win11") },
    server: { label: "Server", test: (r) => r.os.some((o) => o.startsWith("srv")) },
    bios: { label: "HP and Dell BIOS", test: (r) => /\b(hp|dell|bios|uefi|firmware)\b/i.test(`${r.title} ${r.detail}`) },
  };
  const counts = Object.fromEntries(Object.entries(ISSUE_TABS).map(([k, t]) => [k, allIssues.filter(t.test).length]));
  // Default: every issue, each listed once with what it applies to. The other tabs narrow it.
  const savedTab = pref.get("issueTab2", "");
  const scope = ISSUE_TABS[savedTab] ? savedTab : "all";
  const appliesTo = (os) => {
    const parts = [];
    if (os.includes("win11")) parts.push("Windows 11");
    const srv = os.filter((o) => o.startsWith("srv")).map((o) => o.slice(3)).sort();
    if (srv.length) parts.push(srv.length === 3 ? "Server" : `Server ${srv.join(", ")}`);
    return parts.length ? `Applies to: ${parts.join(", ")}` : "";
  };
  const issues = allIssues.filter(ISSUE_TABS[scope].test);
  const scopeLabel = ISSUE_TABS[scope].label;
  const issuesBody = data("knownIssues")
    ? `<div class="card">
        <div class="seg" role="tablist" aria-label="Known issue filter">${Object.entries(ISSUE_TABS)
          .map(([k, t]) => `<button type="button" role="tab" data-issue-tab="${k}" aria-selected="${k === scope}">${esc(t.label)} (${counts[k]})</button>`)
          .join("")}</div>
        ${hiddenByOs ? `<p class="meta">${hiddenByOs} more ${hiddenByOs === 1 ? "issue is" : "issues are"} hidden by the ${esc(OS[state.os])} filter at the top. Choose All there to see ${hiddenByOs === 1 ? "it" : "them"}.</p>` : ""}
        ${issues.length ? `<ul class="list">${issues
          .map((r) => `<li><span class="row-title">${link(r.url, r.title)}</span> ${pill(r.status, /resolved/i.test(r.status) ? "ok" : "warn")} ${pill(appliesTo(r.os))}
            <div class="meta">${esc(r.sources.join(", "))}${r.updated ? ` · updated ${esc(stamp(r.updated))}` : ""}</div><p>${esc(r.detail)}</p></li>`)
          .join("")}</ul>` : `<p>No open or recent ${esc(scopeLabel)} known issues${state.os === "all" ? "" : ` for ${esc(OS[state.os])}`}.</p>`}
        <p class="meta">From Windows release health. Resolved items are kept for 45 days. ${(data("knownIssues").pages || []).map((pg) => link(pg.url, pg.label)).join(" · ")}</p>
      </div>`
    : sectionError("knownIssues", "Windows release health");

  const sense = senseInfo();
  const channelRows = [
    ["Security intelligence", data("intelligence")?.securityIntelligence, "No ring. The definitions page does not assign one."],
    ["Engine", data("intelligence")?.engine, "No ring is published next to this version."],
    ["Platform", data("intelligence")?.platform, "Same as the engine."],
    ["Sense (MsSense.exe)", sense.version, sense.channel || "Not stated in the Update Catalog."],
  ];
  const channels = `<div class="card">
    <div class="table-wrap"><table><thead><tr><th>Component</th><th>Current version</th><th>Ring</th></tr></thead><tbody>${channelRows
      .map(([a, v, r]) => `<tr><td>${esc(a)}</td><td class="mono">${v ? esc(v) : na()}</td><td>${esc(r)}</td></tr>`)
      .join("")}</tbody></table></div>
    <p style="margin-top:10px">Defender has three separate update channel settings: engine, platform and security intelligence. Each one decides when in Microsoft's gradual rollout a device takes a new release.</p>
    <ul>
      <li><strong>Engine and platform:</strong> Beta Channel, then Current Channel (Preview), then Current Channel (Staged), then Current Channel (Broad). Critical: Time delay holds a release back further.</li>
      <li><strong>Security intelligence:</strong> Current Channel (Staged) or Current Channel (Broad). It ships several times a day.</li>
    </ul>
    ${source("https://learn.microsoft.com/en-us/defender-endpoint/manage-gradual-rollout", "Manage the gradual rollout process for Microsoft Defender updates")}
  </div>`;

  const stories = oobStories();
  const since = p.last ? stamp(p.last).split(",")[0].replace(/\s*\(date only\)/, "") : "the last Patch Tuesday";
  const oobBody = `<div class="card">
    <p>No out-of-band Defender security-intelligence or engine release since ${esc(since)}. Security intelligence ships several times a day and the engine monthly, so neither has an "out-of-band" release in the Windows sense; this line changes if Microsoft or the news feeds report one.</p>
    <h3 style="margin-top:10px">Zero-day and out-of-band stories since ${esc(since)}</h3>
    ${stories.length ? `<ul class="list">${stories
      .map((n) => `<li id="story-${esc(slugId(n.url))}"><span class="row-title">${link(n.url, n.title)}</span><div class="meta">${esc(n.source)} · ${n.published ? esc(stamp(n.published)) : "time not published"}</div>${n.summary ? `<p>${esc(n.summary)}</p>` : ""}</li>`)
      .join("")}</ul>` : `<p class="meta">None in the news feeds.</p>`}
    <p class="meta">This is the one place these stories are shown. The alert banner and the news feed link here.</p>
  </div>`;

  return [
    section("out-of-band", "Out-of-band and zero-day", oobBody, "news"),
    section("patch-tuesday", "Patch Tuesday", ptBody, "patchTuesday", ptLine),
    section("qualys", "Qualys QIDs for this Patch Tuesday", qualysBody, "qualys"),
    section("exploited", "Exploited and zero-day", kevBody, "kev"),
    section("known-issues", "Known issues", issuesBody, "knownIssues"),
    section("channels", "Update channels", channels),
  ].join("");
}

// ---------- Intune tab ----------
function renderIntune() {
  const compliance = `<div class="card">
    <p>The Windows compliance policy in Intune has two Microsoft Defender Antimalware checks:</p>
    <ul>
      <li><strong>Microsoft Defender Antimalware security intelligence up-to-date</strong>: a yes or no check. It uses Defender's own out-of-date flag on the device. There is no setting for a custom number of days.</li>
      <li><strong>Microsoft Defender Antimalware minimum version</strong>: the lowest allowed Defender client version, for example 4.18.xxxx.x. The Status tab shows which platform versions are still within N-2.</li>
    </ul>
    <p><strong>Require BitLocker</strong> is read through Device Health Attestation, which is measured at boot. A device that finishes encrypting only reports compliant after its next restart. After a BIOS or firmware update, BitLocker can be suspended until it is resumed, which shows as non-compliant. That is not an antivirus failure.</p>
    ${source("https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-create-windows", "Windows compliance settings in Intune")}
  </div>`;

  const intune = data("intune");
  // One heading per week (the collector merges split headings); weeks with nothing for Windows or security are left out.
  const weekList = [];
  for (const w of intune?.weeks || []) {
    const date = w.week.replace(/\s*\(.*$/, "").trim();
    const same = weekList.find((x) => x.week.replace(/\s*\(.*$/, "").trim() === date);
    if (same) {
      same.items = [...same.items, ...w.items];
      if (w.week.length > same.week.length) same.week = w.week;
    } else weekList.push({ ...w });
  }
  const filledWeeks = weekList.filter((w) => w.items.length);
  const skipped = weekList.length - filledWeeks.length;
  const weeks = intune
    ? `<div class="card">${filledWeeks
        .slice(0, 6)
        .map((w) => `<h3>${esc(w.week)}</h3><ul class="list" style="margin-bottom:12px">${w.items.map((i) => `<li><span class="row-title">${link(i.url, i.name)}</span><p>${esc(i.summary)}</p></li>`).join("")}</ul>`)
        .join("")}${skipped ? `<p class="meta">${skipped} recent ${skipped === 1 ? "week has" : "weeks have"} no Windows or security items and ${skipped === 1 ? "is" : "are"} not shown.</p>` : ""}${source(intune.url, "Intune what's new")}</div>`
    : sectionError("intune", "Intune what's new");
  const dev = intune?.inDevelopment?.length
    ? `<div class="card"><p class="meta">${intune.inDevelopment.length} Windows, security or Endpoint Privilege Management items Microsoft lists as in development.</p><ul class="list">${intune.inDevelopment.map((i) => `<li><span class="row-title">${esc(i.name)}</span><p>${esc(i.summary)}</p></li>`).join("")}</ul>${source(intune.inDevelopmentUrl, "In development for Intune")}</div>`
    : `<div class="card"><p>${intune ? "No Windows or security items, or the page could not be read." : "Not available yet."}</p>${source("https://learn.microsoft.com/en-us/intune/whats-new/in-development", "In development for Intune")}</div>`;

  return [
    section("compliance", "Intune compliance: antivirus, versions and BitLocker", compliance),
    section("intune-weekly", "Intune weekly notes (Windows and security)", weeks, "intune"),
    section("intune-dev", "Intune in development", dev),
    section("roadmap", "Microsoft 365 roadmap: Defender and Intune", renderRoadmap(), "roadmap"),
  ].join("");
}

function renderRoadmap() {
  const r = data("roadmap");
  if (!r) return `<div class="card"><p class="meta">${esc(sec("roadmap")?.detail || "Not checked yet.")} Microsoft's public roadmap feed is often unavailable; this section fills in when it answers.</p>${source("https://www.microsoft.com/microsoft-365/roadmap", "Microsoft 365 roadmap")}</div>`;
  const mode = pref.get("roadmapMode", "core");
  const hasCore = r.rows.some((i) => "core" in i);
  const rows = mode === "core" && hasCore ? r.rows.filter((i) => i.core) : r.rows;
  const seg = hasCore
    ? `<div class="seg" role="tablist" aria-label="Roadmap filter"><button type="button" role="tab" data-roadmap="core" aria-selected="${mode === "core"}">Defender and Intune (${r.rows.filter((i) => i.core).length})</button><button type="button" role="tab" data-roadmap="all" aria-selected="${mode === "all"}">All stored items (${r.rows.length})</button></div>`
    : "";
  return `<div class="card">${seg}${rows.length ? `<ul class="list">${rows
    .map((i) => `<li><span class="row-title">${link(i.url, i.title)}</span> ${pill(i.status || "Roadmap", /launched|rolling/i.test(i.status) ? "ok" : "")}${i.release ? ` <span class="meta">${esc(i.release)}</span>` : ""}<p>${esc(i.description)}</p></li>`)
    .join("")}</ul>` : "<p>No Defender or Intune items in the feed right now.</p>"}${source(r.url, "Microsoft 365 roadmap")}</div>`;
}

// ---------- Detections tab: changelog ----------
// Windows only. The data files are already filtered when they are built; this is a second check in the browser.
// Same rule as scripts/lib/platform.mjs: Linux, macOS, Android, iOS, Unix and Unix-side scripts (PHP, Perl, Ruby, shell) are not shown.
const NON_WIN_PLATFORM = /^[^:\/]+:(?:Linux|MacOS(?:_X|X)?|OSX|Mac|AndroidOS|Android|iOS|iPhoneOS|iPadOS|Unix|FreeBSD|BSD|Solaris|AIX|SH|Bash|ELF|SymbOS|PHP|Perl|Ruby)\//i;
const isWin = (n) => !NON_WIN_PLATFORM.test(n);

function changelogHistory() {
  const clData = data("changelog");
  return clData?.history?.length ? clData.history : clData ? [clData] : [];
}

// Older builds' detections live in their own files and load when picked.
state.builds = {};
const BUILD_TIMEOUT_MS = 10000;

function buildRows(h) {
  if (!h) return { status: "none", rows: [] };
  if (state.builds[h.version]) return state.builds[h.version];
  if (Array.isArray(h.rows)) return { status: "ok", rows: h.rows };
  const latest = data("changelog");
  if (latest && h.version === latest.version && Array.isArray(latest.rows)) return { status: "ok", rows: latest.rows };
  return state.builds[h.version] || { status: "idle", rows: [] };
}

async function loadBuild(h) {
  if (!h?.file) return;
  const cur = state.builds[h.version];
  if (cur && (cur.status === "loading" || cur.status === "ok")) return;
  state.builds[h.version] = { status: "loading", rows: [] };
  rerenderChangelog();
  try {
    const json = await getJson(h.file, BUILD_TIMEOUT_MS, 0);
    state.builds[h.version] = { status: "ok", rows: json.rows || [] };
  } catch (e) {
    state.builds[h.version] = { status: "error", rows: [], error: e?.name === "TimeoutError" ? "timeout" : String(e?.message || e) };
  }
  rerenderChangelog();
}

function rerenderChangelog() {
  const el = document.getElementById("changelog");
  if (!el) return;
  const focusId = document.activeElement?.id;
  el.outerHTML = section("changelog", "Detections in security intelligence", renderChangelog(), "changelog");
  if (focusId) document.getElementById(focusId)?.focus();
}

function selectedBuild() {
  const history = changelogHistory();
  // A picked build is remembered only while it was picked against the current latest build; a new build resets to latest.
  const pick = pref.get("siPick", null);
  const wanted = pick && pick.latest === history[0]?.version ? pick.version : "";
  const idx = Math.max(0, history.findIndex((h) => h.version === wanted));
  return { history, idx, h: history[idx], prev: history[idx + 1] };
}

const SEV_TONE = { severe: "bad", high: "warn", medium: "", low: "" };

function renderChangelog() {
  const clData = data("changelog");
  if (!clData) {
    const s = sec("changelog");
    return `<div class="card"><p>${/timed out/i.test(s?.detail || "") ? "The detection changelog timed out on the last check." : "The detection changelog could not be read on the last check."} ${esc(s?.detail || "")}</p>
      <button type="button" class="btn" data-action="retry">Retry</button> <span class="meta">Retry reloads the latest published data file. The changelog itself is re-read at the next scheduled refresh.</span></div>`;
  }
  const { history, idx, h, prev } = selectedBuild();
  const cur = buildRows(h);
  const before = buildRows(prev);
  if (cur.status === "idle") setTimeout(() => loadBuild(h));
  if (prev && before.status === "idle") setTimeout(() => loadBuild(prev));
  const q = (state.threatQ || "").trim().toLowerCase();
  const rows = cur.rows.filter((r) => isWin(r.name) && (!q || r.name.toLowerCase().includes(q)));
  const nAdded = h.added ?? cur.rows.filter((r) => r.change === "added").length;
  const nUpdated = h.updated ?? cur.rows.filter((r) => r.change === "updated").length;
  let delta = "";
  let diffList = "";
  if (prev) {
    const pAdded = prev.added ?? before.rows.filter((r) => r.change === "added").length;
    const pUpdated = prev.updated ?? before.rows.filter((r) => r.change === "updated").length;
    let names = "";
    if (cur.status === "ok" && before.status === "ok") {
      const was = new Set(before.rows.map((r) => r.name));
      const now = new Set(cur.rows.map((r) => r.name));
      const fresh = cur.rows.filter((r) => !was.has(r.name) && isWin(r.name));
      const gone = before.rows.filter((r) => !now.has(r.name) && isWin(r.name));
      const li = (r, kind) => `<li><span class="${kind === "New" ? "diff-new" : "diff-gone"}">${kind}</span> ${link(r.url, r.name)}</li>`;
      names = ` ${fresh.length} names only on ${esc(h.version)} · ${gone.length} only on ${esc(prev.version)}.`;
      diffList = fresh.length || gone.length
        ? `<details class="diff"${fresh.length + gone.length <= 40 ? " open" : ""}><summary>New or removed versus ${esc(prev.version)}</summary>
            <p class="meta">Names on one build's changelog page and not the other's. A changelog page lists that build's additions and updates, not the full signature catalog, so "removed" means not repeated, not withdrawn.</p>
            <ul class="list compact">${fresh.map((r) => li(r, "New")).join("")}${gone.map((r) => li(r, "Removed")).join("")}</ul></details>`
        : "";
    }
    delta = `<div class="delta"><strong>${esc(prev.version)} → ${esc(h.version)}</strong>: ${nAdded} added (was ${pAdded}), ${nUpdated} updated (was ${pUpdated}).${names}</div>${diffList}`;
  } else if (history.length > 1) delta = `<div class="delta">This is the oldest build kept, so there is no earlier build to compare.</div>`;
  const status = cur.status === "loading" || cur.status === "idle" ? ` ${pill("Loading this build", "warn")}` : "";
  let table;
  if (cur.status === "loading" || cur.status === "idle") table = `<div class="skeleton" style="height:180px" aria-label="Loading this build"></div>`;
  else if (cur.status === "error")
    table = `<div class="notice">${cur.error === "timeout" ? `Build ${esc(h.version)} did not load within ${BUILD_TIMEOUT_MS / 1000} seconds.` : `Build ${esc(h.version)} did not load (${esc(cur.error)}).`} <button type="button" class="btn small" data-action="retry-build" data-version="${esc(h.version)}">Retry</button></div>`;
  else if (rows.length)
    table = `<div class="table-wrap"><table><thead><tr><th>Detection</th><th>Severity</th></tr></thead><tbody>${rows
      .map((r) => `<tr><td><span class="mono">${link(r.url, r.name)}</span><div class="meta">${esc(r.change)} · released ${h.releasedAt ? esc(stamp(h.releasedAt)) : "time not published"}</div></td><td>${r.severity ? pill(r.severity, SEV_TONE[String(r.severity).toLowerCase()] || "") : ""}</td></tr>`)
      .join("")}</tbody></table></div><p class="meta">All ${rows.length} rows shown.</p>`;
  else table = `<p class="meta" style="margin-top:8px">${q ? `No detection in ${esc(h.version)} matches "${esc(state.threatQ)}".` : "Microsoft lists no Windows detections for this build."}</p>`;
  return `<div class="card">
    <p><strong>${esc(h.version)}</strong>${status} · ${h.releasedAt ? esc(stamp(h.releasedAt)) : na("Time not published")} · ${nAdded} added, ${nUpdated} updated</p>
    ${cur.status === "ok" ? `<p class="meta">${cur.rows.filter((r) => isWin(r.name)).length} Windows detection names. Windows only: Linux, macOS, Android and iOS detections are not tracked here. The OS chips at the top do not change this list.</p>` : ""}
    <div class="controls">
      ${history.length > 1 ? `<label class="field">Build <select id="si-version">${history.map((x, i) => `<option value="${esc(x.version)}" ${i === idx ? "selected" : ""}>${esc(x.version)}${i === 0 ? " (latest)" : ""}${x.releasedAt ? ` · ${esc(stamp(x.releasedAt).split(" · ")[0])}` : ""}</option>`).join("")}</select></label>` : ""}
      <label class="field" style="flex:1 1 220px">Threat name <input type="search" id="threat-q" value="${esc(state.threatQ || "")}" placeholder="e.g. Trojan:Win32/Xworm" spellcheck="false"></label>
    </div>
    ${delta}
    <div class="controls" style="margin:6px 0">
      <button type="button" class="btn small" data-export="json">Download JSON</button>
      <button type="button" class="btn small" data-export="csv">Download CSV</button>
      <button type="button" class="btn small" data-export="copy">Copy JSON</button>
      <span class="meta">Exports the rows shown, for build ${esc(h.version)}.</span>
    </div>
    <div id="cl-table">${table}</div>
    <p class="meta">Older builds load from this site's own data when picked. If one takes longer than ${BUILD_TIMEOUT_MS / 1000} seconds, use Retry. <button type="button" class="btn small" data-action="retry-build" data-version="${esc(h.version)}">Retry</button></p>
    ${source(clData.url, "Security intelligence release notes")}
  </div>`;
}

function exportRows() {
  const { h } = selectedBuild();
  if (!h) return { version: "", rows: [] };
  const q = (state.threatQ || "").trim().toLowerCase();
  return { version: h.version, releasedAt: h.releasedAt || "", rows: buildRows(h).rows.filter((r) => isWin(r.name) && (!q || r.name.toLowerCase().includes(q))) };
}

function renderTrend() {
  const history = changelogHistory();
  if (!history.length) return sectionError("changelog", "The detection changelog");
  const added = (h) => h.added ?? buildRows(h).rows.filter((r) => r.change === "added").length;
  const max = Math.max(1, ...history.map(added));
  const peak = history.reduce((a, h) => (added(h) > added(a) ? h : a), history[0]);
  // Oldest on the left so the chart reads forward in time; the table below holds every value.
  const bars = [...history].reverse().map((h) => {
    const n = added(h);
    const when = h.releasedAt ? stamp(h.releasedAt) : "time not published";
    const label = h === history[0] || h === peak ? `<span class="si-bar-val">${n}</span>` : "";
    return `<div class="si-bar-col" tabindex="0" title="${esc(`${h.version}: ${n} new detections · ${when}`)}" aria-label="${esc(`${h.version}: ${n} new detections, released ${when}`)}">
      <div class="si-bar-track">${label}<div class="si-bar" style="height:${Math.max(2, Math.round((n / max) * 100))}%"></div></div>
      <span class="si-bar-x">${esc(h.version.split(".")[2])}</span></div>`;
  }).join("");
  // The oldest kept build has nothing earlier to compare with, so it is left out.
  const notable = history.slice(0, -1).flatMap((h) => (h.newFamilies || []).map((n) => ({ v: h.version, n })));
  return `<div class="card">
    <h3>New detections per build</h3>
    <div class="si-bars" role="group" aria-label="New detections per security intelligence build, oldest to newest">${bars}</div>
    <p class="meta">Bars are labelled with the build number's third part (1.463.<strong>497</strong>.0). Hover or focus a bar for its count and time; every value is in the table below.</p>
    ${notable.length ? `<h3 style="margin-top:12px">Notable new detections</h3><p class="meta">Windows detections whose family this tracker had not seen in any earlier build it keeps (generic families such as Wacatac are left out).</p><ul class="list compact">${notable.slice(0, 12).map((x) => `<li><span class="mono">${esc(x.v)}</span> · ${esc(x.n)}</li>`).join("")}</ul>` : ""}
  </div>
  <div class="card table-wrap" style="margin-top:12px"><table><thead><tr><th>Build</th><th>Released (UTC)</th><th>Released (Chicago)</th><th>Added</th><th>Updated</th></tr></thead><tbody>${history
    .map((h, i) => {
      const [utc, chi] = h.releasedAt ? stamp(h.releasedAt).split(" · ") : ["Time not published", ""];
      return `<tr><td class="mono">${esc(h.version)}${i === 0 ? ` ${pill("Latest", "ok")}` : ""}</td><td>${esc(utc)}</td><td>${esc(chi || "")}</td><td>${h.added ?? buildRows(h).rows.filter((r) => r.change === "added").length}</td><td>${h.updated ?? buildRows(h).rows.filter((r) => r.change === "updated").length}</td></tr>`;
    })
    .join("")}</tbody></table><p class="meta" style="margin-top:6px">The last ${history.length} builds in Microsoft's detection changelog. Microsoft's changelog clock has no time zone; it is read as UTC (see the Security intelligence card for the evidence). Chicago times carry CST or CDT.</p></div>`;
}

function renderFeatures() {
  const mde = data("mde");
  if (!mde) return sectionError("mde", "Defender for Endpoint what's new");
  const seen = new Map();
  for (const i of mde.items) {
    const k = i.name.toLowerCase();
    if (!seen.has(k)) seen.set(k, { ...i, history: [...(i.history || [])] });
    else seen.get(k).history.push({ stage: i.stage, when: i.when });
  }
  const items = [...seen.values()].slice(0, 20);
  return `<div class="card"><ul class="list">${items
    .map((i, n) => {
      const also = i.history?.length ? ` <span class="meta">(also listed: ${i.history.map((h) => `${esc(h.stage)} ${esc(h.when)}`).join(", ")})</span>` : "";
      const long = (i.text || "").length > 220;
      return `<li><span class="row-title">${link(i.url, i.name)}</span> ${pill(i.stage, i.stage === "GA" ? "ok" : "")} <span class="meta">${esc(i.when)} · ${esc(i.type)}</span>${also}
        <p class="${long ? "clamp" : ""}" id="feat-${n}">${esc(i.text)}</p>${long ? `<button type="button" class="linkbtn" data-expand="feat-${n}" aria-expanded="false">Read more</button>` : ""}</li>`;
    })
    .join("")}</ul>
    <p class="meta">Source: Microsoft's Defender for Endpoint what's new page. Windows rows that Microsoft lists more than once (for example in preview and again at GA) are listed here once.</p>
    ${source(mde.url, "What's new in Defender for Endpoint")}</div>`;
}

function renderFeed() {
  const homeIds = new Set(oobStories().map((n) => n.url));
  const news = (data("news")?.items || []).filter((n) => osOk(n.os)).map((n) => ({ ...n, kind: "news", where: n.source }));
  const posts = (data("community")?.posts || []).map((p) => ({ ...p, kind: "reddit", where: p.community }));
  const filter = pref.get("feedFilter", "all");
  const DEF = /defender|mde\b|mssense|senseir|intune|antivirus|edr\b/i;
  const tests = {
    all: () => true,
    defender: (x) => DEF.test(`${x.title} ${x.summary || ""}`),
    windows: (x) => x.kind === "news" && !DEF.test(`${x.title} ${x.summary || ""}`),
    reddit: (x) => x.kind === "reddit",
  };
  const all = [...news, ...posts].sort((a, b) => (b.published || "").localeCompare(a.published || ""));
  const items = all.filter(tests[filter] || tests.all);
  const count = (k) => all.filter(tests[k]).length;
  const failed = [
    ...(data("news")?.feeds || []).filter((f) => !f.ok).map((f) => f.source),
    ...(data("community")?.subs || []).filter((x) => !x.ok).map((x) => `r/${x.sub}`),
  ];
  const seg = `<div class="seg" role="tablist" aria-label="Feed filter">${[
    ["all", "All"],
    ["defender", "Defender"],
    ["windows", "Windows endpoint"],
    ["reddit", "Reddit"],
  ]
    .map(([k, l]) => `<button type="button" role="tab" data-feed="${k}" aria-selected="${k === filter}">${l} (${count(k)})</button>`)
    .join("")}</div>`;
  if (!data("news") && !data("community")) return sectionError("news", "The news feeds");
  return `<div class="card">${seg}
    ${items.length ? `<ul class="list">${items
      .slice(0, 40)
      .map((x) =>
        homeIds.has(x.url)
          ? `<li>${pill("Zero-day", "bad")} A zero-day story from ${esc(x.where)} is shown under <a href="#out-of-band">Out-of-band and zero-day</a>.</li>`
          : `<li><span class="row-title">${link(x.url, x.title)}</span> ${x.kind === "reddit" ? pill("Reddit") : ""}<div class="meta">${esc(x.where)} · ${x.published ? esc(stamp(x.published)) : "time not published"}</div>${x.summary ? `<p>${esc(x.summary)}</p>` : ""}</li>`,
      )
      .join("")}</ul>` : "<p>Nothing matches this filter.</p>"}
    <p class="meta">${failed.length ? `Not loaded on the last refresh: ${esc(failed.join(", "))}. Retried at the next scheduled refresh. ` : "All news feeds and subreddits loaded on the last refresh. "}Reddit posts are community posts, not Microsoft guidance: r/DefenderATP in full, r/Intune and r/sysadmin only when a post mentions Defender.</p>
  </div>`;
}

function renderHashes() {
  const d = data("hashes");
  const hashes = d?.rows || [];
  const short = (h) => `${h.slice(0, 12)}…${h.slice(-6)}`;
  const vtSet = d && d.vtStatus && d.vtStatus !== "no-key";
  const vtCell = (h) => {
    const v = h.vtResult;
    if (!vtSet) return `<span class="na">${d?.vtStatus === "no-key" ? "VirusTotal key not set" : "Not checked yet"}</span>`;
    if (!v) return `<span class="na">Queued for the next refresh</span>`;
    if (v.error) return `${pill("Lookup failed, retrying", "warn")}<div class="meta">${esc(v.error)}</div>`;
    if (!v.found) return `<span class="meta">Not in VirusTotal</span>`;
    const ms = `Microsoft: ${esc(v.microsoft || v.microsoftState)}`;
    return `${v.gap ? pill("Gap", "bad") : v.microsoft ? pill("Microsoft detects", "ok") : pill("No engine detects", "")} <div class="meta">${v.malicious}/${v.total} engines · ${ms}</div>`;
  };
  const gaps = hashes.filter((h) => h.vtResult?.gap).length;
  const analysed = hashes.filter((h) => h.vtResult && h.vtResult.found !== undefined).length;
  const status = !d
    ? ""
    : d.vtStatus === "no-key"
      ? `<div class="notice">VirusTotal key not set. Add the repository secret <code>VIRUSTOTAL_API_KEY</code> to check these hashes. The OTX column works without it.</div>`
      : !vtSet
        ? `<p class="meta">VirusTotal has not been asked yet; the next refresh does it.</p>`
        : `<p><strong>${analysed} of ${hashes.length}</strong> analysed on VirusTotal · <strong>${gaps}</strong> that other engines detect and Microsoft does not.${d.vtStatus === "rejected" ? ` ${pill("VirusTotal rejected the key", "bad")} <span class="meta">${esc((d.vtNote || "").replace(/^VirusTotal rejected the key /, ""))}</span>` : d.vtStatus === "limited" ? ` ${pill("Rate limit reached, continuing next refresh", "warn")}` : ""}</p>`;
  return `<div class="card">
    <p>SHA-256 hashes posted publicly (TweetFeed), checked on VirusTotal and AlienVault OTX. A row marked <strong>Gap</strong> is one where other engines detect the file and Microsoft does not: a candidate to submit to Microsoft.</p>
    ${status}
    ${d ? (hashes.length ? `<div class="table-wrap"><table><thead><tr><th>Hash</th><th>Reported</th><th>VirusTotal</th><th>Defender (OTX)</th><th>Last checked</th><th>Links</th></tr></thead><tbody>${hashes
      .map((h) => `<tr><td class="mono" title="${esc(h.hash)}">${esc(short(h.hash))} <button type="button" class="btn small" data-copy="${esc(h.hash)}" aria-label="Copy hash">Copy</button>${h.vtResult?.fileType || h.fileType ? `<div class="meta">${esc(h.vtResult?.fileType || h.fileType)}</div>` : ""}</td>
        <td>${h.reportedAt ? esc(stamp(h.reportedAt)) : ""}${h.reporter ? `<div class="meta">${esc(h.reporter)}</div>` : ""}</td>
        <td>${vtCell(h)}</td>
        <td>${h.defender ? esc(h.defender) : h.analysed ? pill(h.other ? "Gap" : "Not detected", h.other ? "bad" : "") : `<span class="meta">No OTX analysis</span>`}${h.other ? `<div class="meta">Other: ${esc(h.other)}</div>` : ""}</td>
        <td class="meta">${esc(stamp(h.vtResult?.checkedAt || h.checkedAt || sec("hashes").lastOkAt || sec("hashes").checkedAt))}</td>
        <td>${link(h.vt, "VirusTotal")} · ${link(h.otx, "OTX")}</td></tr>`)
      .join("")}</tbody></table></div>` : "<p>No Windows hashes in the feed yet.</p>") : sectionError("hashes", "The public hash feed")}
    <p class="meta" style="margin-top:8px">Third-party, unvetted data. VirusTotal is asked at most 4 times a minute and 500 times a day, and each answer is kept for 24 hours. The latest 20 Windows hashes are kept. Windows only: a file for Android, Linux, macOS or iOS is left out: by its TweetFeed tags, or once VirusTotal shows what it is (a ZIP is judged by its contents).${d?.excluded?.length ? ` ${d.excluded.length} left out so far.` : ""}</p>
    <form id="hash-form" class="controls" style="margin-top:10px">
      <label class="field" style="flex:1 1 260px">Look up a hash <input type="text" id="hash-q" placeholder="MD5, SHA-1 or SHA-256" autocomplete="off" spellcheck="false"></label>
      <button type="submit" class="btn" style="align-self:end">Check Microsoft detection</button>
    </form>
    <p class="meta">Opens the hash on VirusTotal (which lists Microsoft's verdict) and on AlienVault OTX, in new tabs. Nothing is sent from this site.</p>
  </div>`;
}

// ---------- Sense tab ----------
const STAGES = ["Community reports", "Microsoft acknowledged", "Fix announced", "Fix published"];
/** A date-only value (the catalog and stage dates) in UTC and Chicago, or a full stamp for a time. */
const dayOrStamp = (v) => (/^\d{4}-\d{2}-\d{2}$/.test(v || "") ? senseReleaseStamp(v).replace(" (time of day not published)", "") : stamp(v));

function renderSenseReleases() {
  const sd = data("sense");
  const releases = sd?.releases || [];
  if (!releases.length) return sectionError("sense", "The Sense release history") || `<div class="card"><p class="meta">No Sense release recorded yet. The first refresh after this update fills it from the Update Catalog.</p></div>`;
  const rows = releases
    .map((r, i) => {
      const catalog = (r.catalog || []).map((c) => `<div>${esc(c.os)}: ${c.date ? esc(dayOrStamp(c.date)) : "date not published"}${c.channel ? ` · ${esc(c.channel)}` : ""}</div>`).join("");
      return `<tr>
        <td class="mono">${esc(r.version)}${i === 0 ? ` ${pill("Latest", "ok")}` : ""}</td>
        <td>${r.released ? esc(dayOrStamp(r.released)) : na("Not published")}<div class="meta">First seen by this tracker ${esc(dayOrStamp(r.firstSeen))}</div></td>
        <td>${r.os?.length ? esc(r.os.join(", ")) : na("Not in the catalog")}${catalog ? `<details><summary class="meta">Catalog dates per OS</summary><div class="meta">${catalog}</div></details>` : ""}</td>
        <td>${r.restart ? esc(r.restart) : na("Not stated")}</td>
        <td>${r.rings?.length ? r.rings.map((x) => pill(x)).join(" ") : na("Not stated")}</td>
      </tr>`;
    })
    .join("");
  return `<div class="card">
    <p>Every Sense (MsSense.exe) build this tracker has seen in the Microsoft Update Catalog for KB5005292, newest first. A build stays listed after the catalog drops it. The catalog publishes a date per OS family, not a time of day. Restart text comes from the KB5005292 page and applies to the build that page names.</p>
    <div class="table-wrap"><table><thead><tr><th>Version</th><th>Released (catalog)</th><th>OS scope</th><th>Restart</th><th>Ring</th></tr></thead><tbody>${rows}</tbody></table></div>
    ${source(sd.url, "Microsoft Update Catalog: KB5005292")}
  </div>`;
}

function renderSenseKb() {
  const kb = data("sense")?.kb;
  if (!kb) return `<div class="card"><p class="meta">The KB5005292 page has not been read yet.</p>${source("https://support.microsoft.com/en-us/servicing/management-tools/microsoft-defender/update/microsoft-defender-for-endpoint-update-for-edr-sensor", "KB5005292")}</div>`;
  const status = kb.ok ? pill("Read on the last refresh", "ok") : kb.stale ? pill("Stale: showing the last good read", "warn") : pill("Not read", "bad");
  return `<div class="card">
    <p>${status}${kb.error ? ` <span class="meta">${esc(kb.error)}</span>` : ""}</p>
    <dl class="facts">
      <dt>Version named</dt><dd>${kb.version ? `<code>${esc(kb.version)}</code>` : na("Not found on the page")}</dd>
      <dt>Known issues</dt><dd>${kb.knownIssues ? esc(kb.knownIssues) : na("No known-issues text found. That is not the same as no known issues.")}</dd>
      <dt>Restart requirement</dt><dd>${kb.restart ? esc(kb.restart) : na("Not found on the page")}</dd>
    </dl>
    ${source(kb.url, "KB5005292: Defender for Endpoint update for EDR sensor")}
  </div>`;
}

function stageTrack(issue) {
  const at = STAGES.indexOf(issue.stage);
  return `<ol class="stages">${STAGES.map((st, i) => {
    const r = issue.reached?.[st];
    const cls = i <= at ? (i === at ? "done current" : "done") : "";
    return `<li class="${cls}"><span class="stage-name">${esc(st)}</span>${r ? `<span class="meta">${esc(dayOrStamp(r.at))}</span><span class="meta">${r.url ? link(r.url, r.note) : esc(r.note)}</span>` : `<span class="meta">Not yet</span>`}</li>`;
  }).join("")}</ol>`;
}

function renderSenseIssues() {
  const issues = data("sense")?.issues || [];
  if (!issues.length) return `<div class="card"><p class="meta">No Sense issues are being tracked. Add one under senseIssues in data/curated.json.</p></div>`;
  return `<div class="card"><p>Each reported Sense problem is followed until Microsoft ships a fix. The scheduled refresh moves an issue forward when the KB5005292 known-issues text or Windows release health mentions it, when Microsoft says a fix is coming or names a fixed build, and when matching news or Reddit posts appear. An issue never moves back. "Inferred" means the KB page stopped listing it after a newer build shipped.</p>
    ${issues
      .map(
        (i) => `<article class="issue">
      <h3>${esc(i.title)} ${pill(i.stage || "Tracked", i.stage === "Fix published" ? "ok" : i.stage === "Community reports" ? "warn" : "")}</h3>
      ${stageTrack(i)}
      <dl class="facts">
        ${i.affected ? `<dt>Affected build</dt><dd><code>${esc(i.affected)}</code></dd>` : ""}
        ${i.scope ? `<dt>Scope</dt><dd>${esc(i.scope)}</dd>` : ""}
        <dt>Symptom</dt><dd>${esc(i.symptom)}</dd>
        <dt>Workaround</dt><dd>${esc(i.workaround || "None published.")}</dd>
        <dt>First reported</dt><dd>${esc(dayOrStamp(i.firstSeen))}</dd>
      </dl>
      ${i.posts?.length ? `<details><summary>Matching posts in the last 14 days (${i.posts.length})</summary><ul class="list">${i.posts.map((p) => `<li>${link(p.url, p.title)}<div class="meta">${esc(p.where)} · ${p.published ? esc(stamp(p.published)) : "time not published"}</div></li>`).join("")}</ul></details>` : ""}
      ${(i.links || []).map((l) => source(l.url, l.label)).join("")}
    </article>`,
      )
      .join("")}</div>`;
}

function renderSenseSignal() {
  const sig = data("sense")?.signal;
  if (!sig) return `<div class="card"><p class="meta">Not computed yet.</p></div>`;
  return `<div class="card"><p>News and Reddit posts from the last 7 days that mention the sensor (Sense, MsSense, KB5005292, a 10.8xxx build) together with a problem word. Unconfirmed until Microsoft posts. Reddit and the news feeds are listed under Source health; when one of them failed, an empty list means unknown, not none.</p>
    ${sig.posts?.length ? `<ul class="list">${sig.posts.map((p) => `<li>${link(p.url, p.title)}<div class="meta">${esc(p.where)} · ${p.published ? esc(stamp(p.published)) : "time not published"}</div></li>`).join("")}</ul>` : `<p class="meta">No matching posts in the last 7 days.</p>`}</div>`;
}

function renderSense() {
  const states = [
    ["Active", "The sensor is reporting. A bad signature still shows up as alerts and quarantines, not as an inactive sensor."],
    ["Impaired communications", "The device cannot fully reach the Defender service URLs, usually because of a proxy. Isolate, live response and file submission fail until that path works."],
    ["No sensor data", "The device reaches the service but sends only partial data. Check that the Connected User Experiences and Telemetry service (DiagTrack) is running and that antivirus was not disabled by policy."],
    ["Inactive", "No signals for about seven days, or the device was offboarded. It is not a signature-version problem."],
  ];
  const sense = senseInfo();
  const sensor = `<div class="card">
    ${sense.version ? `<p><strong>Current sensor build:</strong> <code>${esc(sense.version)}</code>${sense.channel ? ` · ${esc(sense.channel)}` : ""}. ${esc(sense.when)}</p>` : ""}
    <p><strong>MsSense.exe</strong> is the Defender for Endpoint EDR sensor (service name <code>Sense</code>). It collects telemetry and sends it to the Defender portal. Its version is separate from the antivirus platform and is updated through KB5005292.</p>
    <p><strong>SenseIR.exe</strong> runs automated investigation and live response actions. It often starts PowerShell as SYSTEM, which can look alarming in process trees but is expected. Do not add allow indicators or exclusions for either file.</p>
    <p>Sensor health is in the Defender portal's device health reports, not in the antivirus signature version.</p>
    <h3 style="margin-top:12px">Sensor health states</h3>
    <div class="table-wrap"><table><thead><tr><th>State</th><th>What it means</th></tr></thead><tbody>${states.map(([a, b]) => `<tr><td><strong>${esc(a)}</strong></td><td>${esc(b)}</td></tr>`).join("")}</tbody></table></div>
    ${source(SENSOR_TROUBLESHOOT.url, SENSOR_TROUBLESHOOT.title)}
    ${source("https://learn.microsoft.com/en-us/defender-endpoint/check-sensor-status", "Check sensor health state")}
    ${source("https://learn.microsoft.com/en-us/defender-endpoint/fix-unhealthy-sensors", "Fix unhealthy sensors")}
    ${source("https://learn.microsoft.com/en-us/defender-endpoint/device-health-sensor-health-os", "Device health and sensor health reports")}
  </div>`;

  return [
    section("sense-issues", "Sense issue tracker", renderSenseIssues(), "sense"),
    section("sense-releases", "Sense release history", renderSenseReleases(), "sense"),
    section("sense-kb", "KB5005292: known issues and restart", renderSenseKb()),
    section("sense-signal", "Sense community signal", renderSenseSignal(), "community"),
    section("sensor", "Sensor (MsSense / SenseIR)", sensor),
  ].join("");
}

function renderDetectionAlerts() {
  const t = data("threats");
  if (!t) return sectionError("threats", "The detection alerts");
  const alerts = t.alerts || [];
  return `<div class="card"><p>A new security intelligence build added a Defender detection whose family name is exactly a threat named in a news story or vendor research post from the last 14 days. Generic families such as Wacatac or Agent never count. Alerts stay listed for 14 days.</p>
    ${alerts.length ? `<div class="table-wrap"><table><thead><tr><th>Detection added</th><th>Build</th><th>In the news</th><th>Last checked</th></tr></thead><tbody>${alerts
      .map((a) => `<tr><td>${link(a.detectionUrl, a.detection)}${a.severity ? `<div class="meta">${esc(a.severity)}</div>` : ""}</td>
        <td class="mono">${esc(a.version)}<div class="meta">${a.releasedAt ? esc(stamp(a.releasedAt)) : "time not published"}</div></td>
        <td>${link(a.story.url, a.story.title)}<div class="meta">${esc(a.story.source)}${a.story.published ? ` · ${esc(stamp(a.story.published))}` : ""} · names ${esc(a.threat)}</div></td>
        <td class="meta">${esc(stamp(a.checkedAt || sec("threats")?.checkedAt))}</td></tr>`)
      .join("")}</tbody></table></div>` : `<p class="meta">No build in the last 14 days added a detection for a threat in the news.</p>`}
  </div>`;
}

const COVER_TONE = { Yes: "ok", Unclear: "warn", "Lookup failed, retrying": "bad", "Queued for lookup": "", No: "bad" };

function renderVendorCoverage() {
  const t = data("threats");
  if (!t) return sectionError("threats", "The threat coverage");
  const rows = t.coverage || [];
  const feeds = [...(data("vendors")?.feeds || []), ...(data("news")?.feeds || []).filter((f) => !/^M(icrosoft|SRC)/.test(f.source))];
  const kinds = ["Yes", "Unclear", "Lookup failed, retrying", "Queued for lookup"];
  const counts = kinds.map((c) => `${pill(c, COVER_TONE[c])} ${rows.filter((r) => r.coverage === c).length}`).join(" ");
  return `<div class="card">
    <p>Malware and campaign names from the last 30 days of vendor research (CrowdStrike, SentinelOne, Sophos, Bitdefender, ESET, Trend Micro, Unit 42, eSentire, AhnLab ASEC, watchTowr, Check Point Research, Symantec) and the last 14 days of headlines (The Hacker News, BleepingComputer, SecurityWeek), checked against Defender.</p>
    <ul class="list compact">
      <li><strong>Yes</strong>: a Defender detection for this family is in the last 30 days of the detection changelog (every version, not only the latest builds) or in Microsoft's malware encyclopedia. Matching ignores case and accepts a name that begins the other ("Remus" and "RemusStealer").</li>
      <li><strong>Unclear</strong>: the encyclopedia answered and has no entry for the family, and the changelog has none. Defender may still detect it under another name.</li>
      <li><strong>Lookup failed, retrying</strong>: the encyclopedia did not answer. Each refresh tries again; answers are kept for 24 hours.</li>
      <li><strong>Queued for lookup</strong>: not asked yet. Each refresh asks the encyclopedia about 12 names.</li>
    </ul>
    <p>${counts}</p>
    ${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Threat</th><th>Reported by</th><th>Defender</th><th>Why</th><th>Last checked</th></tr></thead><tbody>${rows
      .map((r) => `<tr><td><strong>${esc(r.threat)}</strong></td>
        <td>${link(r.url, r.title)}<div class="meta">${esc(r.vendor)}${r.kind === "news" ? " (news)" : ""}${r.published ? ` · ${esc(stamp(r.published))}` : ""}</div></td>
        <td>${pill(r.coverage, COVER_TONE[r.coverage])}${r.detections?.length ? `<div class="meta mono">${r.detections.map(esc).join("<br>")}</div>` : ""}</td>
        <td class="meta">${esc(r.basis)}${r.coverage !== "Yes" ? ` ${link(`https://www.microsoft.com/en-us/wdsi/threats/threat-search?query=${encodeURIComponent(`Trojan:Win32/${r.threat}`)}`, "Search the encyclopedia ↗")}` : ""}</td>
        <td class="meta">${esc(stamp(r.checkedAt || sec("threats")?.checkedAt))}</td></tr>`)
      .join("")}</tbody></table></div>` : `<p class="meta">No research post or headline in the window names a specific threat.</p>`}
    <p class="meta">${t.indexedVersions ? `${t.indexedVersions} changelog versions (${t.indexedNames} detection names) from the last 30 days are indexed. ` : ""}${feeds.length ? `Feeds: ${feeds.map((f) => `${esc(f.source)} ${f.ok ? pill("Live", "ok") : pill("Failed", "bad")}`).join(" · ")}` : ""}</p>
  </div>`;
}

function renderKevCoverage() {
  const t = data("threats");
  if (!t) return sectionError("threats", "The CISA KEV check");
  const rows = t.kev || [];
  return `<div class="card">
    <p>Every CVE that CISA added to its Known Exploited Vulnerabilities catalog in the last 14 days, any vendor, with CISA's due date. <strong>Detection found</strong> means a Defender detection name in the last 30 days of the changelog, or in the encyclopedia, contains the CVE number. Otherwise it says <strong>No public MDE detection found</strong>; Defender may still block the exploit under a name without the CVE.</p>
    ${rows.length ? `<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Product</th><th>Added</th><th>Due</th><th>Defender</th><th>Last checked</th></tr></thead><tbody>${rows
      .map((r) => `<tr><td>${link(r.url, r.cve)}${/known/i.test(r.ransomware) ? `<div>${pill("Used in ransomware", "bad")}</div>` : ""}</td>
        <td>${esc(`${r.vendor} ${r.product}`.trim())}<div class="meta">${esc(r.name)}</div></td>
        <td>${esc(r.dateAdded)}</td>
        <td>${esc(r.dueDate)}</td>
        <td>${pill(r.coverage, r.detections.length ? "ok" : "warn")}${r.detections.length ? `<div class="meta mono">${r.detections.map(esc).join("<br>")}</div>` : ""}</td>
        <td class="meta">${esc(stamp(r.checkedAt || sec("threats")?.checkedAt))}</td></tr>`)
      .join("")}</tbody></table></div>` : `<p class="meta">CISA added no CVEs in the last 14 days.</p>`}
    ${source("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA Known Exploited Vulnerabilities")}
  </div>`;
}

function renderIntel() {
  const news = (data("news")?.items || []).filter((n) => osOk(n.os));
  const posts = data("community")?.posts || [];
  const chatter = [...news.map((n) => ({ ...n, where: n.source })), ...posts.map((p) => ({ ...p, where: p.community }))]
    .filter((x) => CHATTER.test(`${x.title} ${x.summary}`) && daysOld(x.published) <= 14)
    .sort((a, b) => (b.published || "").localeCompare(a.published || ""));
  const chatterBody = `<div class="card">
    <p>News and Reddit posts from the last 14 days that mention a false positive, a signature revision, a detection storm, or MsSense / SenseIR. One post is a lead. Several are worth reading before trusting a new build.</p>
    ${chatter.length ? `<ul class="list">${chatter
      .slice(0, 10)
      .map((x) => `<li><span class="row-title">${link(x.url, x.title)}</span><div class="meta">${esc(x.where)} · ${x.published ? esc(stamp(x.published)) : "time not published"}</div></li>`)
      .join("")}</ul>` : `<p class="meta">Nothing matches right now. That is a real empty result, not a missing feed (see Source health).</p>`}
  </div>`;

  // Defender for Endpoint changes that Microsoft announces in Intune's what's new and in-development pages.
  const intune = data("intune");
  const MDE_IN_INTUNE = /defender|\bmde\b|antivirus|agent runtime|endpoint security/i;
  const fromIntune = [
    ...(intune?.weeks || []).flatMap((w) => w.items.filter((i) => MDE_IN_INTUNE.test(i.name)).map((i) => ({ ...i, stage: "Released", when: w.week.replace(/^Week of /, "Week of ") }))),
    ...(intune?.inDevelopment || []).filter((i) => MDE_IN_INTUNE.test(i.name) && !/linux|macos|android|ios/i.test(i.name)).map((i) => ({ ...i, stage: "In development", when: "" })),
  ];
  const intuneBlock = intune
    ? `<div class="card" style="margin-bottom:12px"><h3>Defender for Endpoint changes from Intune</h3>${fromIntune.length ? `<ul class="list">${fromIntune
        .map((i) => `<li><span class="row-title">${link(i.url, i.name)}</span> ${pill(i.stage, i.stage === "Released" ? "ok" : "")}${i.when ? ` <span class="meta">${esc(i.when)}</span>` : ""}<p class="clamp">${esc(i.summary)}</p></li>`)
        .join("")}</ul>` : "<p class=\"meta\">No Defender items in Intune's recent notes.</p>"}<p class="meta">From Intune's what's new and in-development pages, Windows only. ${link(intune.url, "Intune what's new ↗")}</p></div>`
    : "";
  const confirmedBy = (f) => fromIntune.find((i) => i.stage === "Released" && f.name.toLowerCase().split(" in intune")[0].split(" ").filter((w) => w.length > 3).every((w) => i.name.toLowerCase().includes(w)));
  // The three late-2026 items carried over from the old build (Local AI agent discovery, agent runtime protection, Execution Containers).
  const reported = (state.catalog?.features || []).filter((f) => f.status === "Reported" || f.listWithReported);
  const onLearn = (f) => (data("mde")?.items || []).find((i) => f.name.toLowerCase().split(" ").filter((w) => w.length > 3).every((w) => i.name.toLowerCase().includes(w)));
  const reportedBlock = reported.length
    ? `<div class="card" style="margin-top:12px"><h3>Reported, not yet confirmed on Microsoft Learn</h3><p class="meta">Items first seen in news or blogs. Each one says when Microsoft has since confirmed it.</p><ul class="list">${reported
        .map((f) => {
          const c = confirmedBy(f);
          const l = onLearn(f);
          const tag = l ? pill("Confirmed on Microsoft Learn", "ok") : c ? pill("Confirmed in Intune what's new", "ok") : pill("Reported", "warn");
          return `<li><span class="row-title">${esc(f.name)}</span> ${tag}<p>${esc(f.summary)}</p>${l ? `<div>${link(l.url, `Learn: ${l.name} ↗`, "src")}</div>` : c ? `<div>${link(c.url, `Intune: ${c.name} ↗`, "src")}</div>` : ""}${source(f.docs)}</li>`;
        })
        .join("")}</ul></div>`
    : "";

  return [
    section("features", "New Defender for Endpoint features", intuneBlock + renderFeatures() + reportedBlock, "mde"),
    section("chatter", "Bad-detection chatter", chatterBody),
    section("news", "News and Reddit", renderFeed(), "news"),
  ].join("");
}

// ---------- Detections tab (#threats) ----------
function renderThreats() {
  return [
    section("changelog", "Detections in security intelligence", renderChangelog(), "changelog"),
    section("si-trend", "Recent security intelligence builds", renderTrend(), "changelog"),
    section("detection-alerts", "Detection alerts: new detections for threats in the news", renderDetectionAlerts(), "threats"),
    section("vendor-coverage", "Threat coverage: vendor research and news", renderVendorCoverage(), "threats"),
    section("kev-coverage", "CISA KEV: newly exploited CVEs", renderKevCoverage(), "kev"),
    section("hashes", "Public hashes and Defender coverage", renderHashes(), "hashes"),
  ].join("");
}

// ---------- section jump row ----------
/** One chip per section on the current tab; a chip scrolls to its section. */
function renderJump() {
  const nav = document.getElementById("jump");
  if (!nav) return;
  const heads = [...document.querySelectorAll("#view > .section[id] > .section-head > h2")];
  const SHORT = { changelog: "Detections", "si-trend": "Recent builds", "vendor-coverage": "Threat coverage", "kev-coverage": "CISA KEV", hashes: "Public hashes", features: "New MDE features" };
  nav.innerHTML = heads.map((h) => {
    const id = h.closest(".section").id;
    return `<a href="#${esc(id)}">${esc(SHORT[id] || h.textContent.split(":")[0])}</a>`;
  }).join("");
  nav.hidden = heads.length < 2;
}

/** Scroll a section just below the sticky header, whatever height the header has on this screen. */
function scrollToSection(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const head = document.querySelector("header.top")?.offsetHeight || 0;
  window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - head - 8 });
}

// ---------- alert banner ----------
function renderAlerts() {
  const alerts = [];
  const go = (hash, text) => `<a href="#${hash}">${esc(text)}</a>`;
  for (const r of data("kev")?.rows || []) {
    if (daysOld(r.dateAdded) <= 21 && osOk(r.os)) alerts.push({ tone: "bad", html: `${r.endpointSecurity ? "Defender/Intune" : "Windows"} vulnerability exploited in the wild: ${esc(r.cve)} ${esc(r.name)}, added to CISA KEV ${esc(stamp(r.dateAdded))}. ${go("exploited", "Details")}` });
  }
  for (const r of data("patchTuesday")?.endpoint || []) {
    if (/critical/i.test(r.severity) && daysOld(r.released) <= 21) alerts.push({ tone: "bad", html: `Critical Defender CVE this month: ${esc(r.cve)} ${esc(r.title)}. ${go("patch-tuesday", "Patch Tuesday")}` });
  }
  for (const i of state.curated?.incidents || []) {
    if (i.status !== "Patched" && daysOld(i.date) <= 60 && !state.failedUrls?.has(i.url)) alerts.push({ tone: "bad", html: `${esc(i.name)} (${esc(i.status.toLowerCase())}). ${go("exploited", "Details")}` });
  }
  // Zero-day and out-of-band stories live in one section; the banner only points to it.
  const oob = oobStories().filter((n) => daysOld(n.published) <= 7 && osOk(n.os));
  if (oob.length && state.tab !== "updates") alerts.push({ tone: "", html: `${oob.length} zero-day or out-of-band ${oob.length === 1 ? "story" : "stories"} in the last 7 days. ${go("out-of-band", "Read under Out-of-band and zero-day")}` });
  const posts = data("community")?.posts || [];
  const recentChatter = [...(data("news")?.items || []), ...posts].filter((x) => CHATTER.test(`${x.title} ${x.summary}`) && daysOld(x.published) <= 3);
  if (recentChatter.length >= 2) alerts.push({ tone: "", html: `${recentChatter.length} posts in the last 3 days mention a possible bad detection or sensor problem. ${go("chatter", "Review these posts")}` });
  for (const i of (data("sense")?.issues || []).filter((x) => x.stage && x.stage !== "Fix published").slice(0, 2)) {
    alerts.push({ tone: "", html: `Sense issue: ${esc(i.title)} (${esc(i.stage)}). ${go("sense-issues", "Sense issue tracker")}` });
  }
  const freshAlerts = (data("threats")?.alerts || []).filter((a) => daysOld(a.releasedAt) <= 3);
  if (freshAlerts.length) alerts.push({ tone: "", html: `${freshAlerts.length} new Defender detection${freshAlerts.length === 1 ? "" : "s"} in the last 3 days for threats in the news, including ${esc(freshAlerts[0].detection)}. ${go("detection-alerts", "Detection alerts")}` });
  const openIssues = (data("knownIssues")?.rows || []).filter((r) => r.scope === "security" && !/resolved/i.test(r.status) && osOk(r.os));
  for (const r of openIssues.slice(0, 2)) alerts.push({ tone: "", html: `Open known issue: ${esc(r.title)} (${esc(r.status)}). ${go("known-issues", "Known issues")}` });
  if (!alerts.length) return "";
  return `<div class="section" role="region" aria-label="Alerts">${alerts
    .slice(0, 6)
    .map((a) => `<div class="notice ${a.tone}">${a.html}</div>`)
    .join("")}</div>`;
}

// ---------- global search ----------
function searchIndex() {
  const out = [];
  const add = (kind, title, text, where, url) => out.push({ kind, title, text: `${title} ${text || ""}`, where, url });
  for (const r of data("patchTuesday")?.endpoint || []) add("CVE", `${r.cve} ${r.title}`, r.severity, "patch-tuesday", r.url);
  for (const r of data("kev")?.rows || []) add("CVE", `${r.cve} ${r.name}`, r.summary, "exploited", r.url);
  for (const i of state.curated?.incidents || []) add("CVE", `${i.id} ${i.name}`, i.summary, "exploited", i.url);
  for (const r of data("knownIssues")?.rows || []) add(/KB\d+/.test(r.status) ? "KB" : "Known issue", `${r.title} (${r.status})`, r.detail, "known-issues", r.url);
  for (const p of Array.isArray(data("packages")) ? data("packages") : []) if (p.kb) add("KB", `${p.kb} ${p.name}`, p.file, "packages", p.page);
  if (data("sense")) add("KB", `KB5005292 Sense (MsSense.exe) ${data("sense").latest?.version || ""}`, "", "sense-releases", data("sense").url);
  for (const r of data("sense")?.releases || []) add("KB", `Sense ${r.version}`, (r.rings || []).join(" "), "sense-releases", data("sense").url);
  for (const i of data("sense")?.issues || []) add("Known issue", `Sense: ${i.title} (${i.stage || "tracked"})`, i.symptom, "sense-issues", i.links?.[0]?.url);
  for (const a of data("threats")?.alerts || []) add("Detection", `${a.detection} (${a.threat})`, a.story.title, "detection-alerts", a.detectionUrl);
  for (const r of data("threats")?.coverage || []) add("Threat", `${r.threat}: Defender ${r.coverage}`, r.title, "vendor-coverage", r.url);
  for (const r of data("threats")?.kev || []) add("CVE", `${r.cve} ${r.vendor} ${r.product}: ${r.coverage}`, r.name, "kev-coverage", r.url);
  const q = data("qualys");
  for (const [m, v] of Object.entries(q?.months || (q ? { [q.month]: q } : {}))) add("QID", `Qualys QIDs for ${m} Patch Tuesday`, (v.qids || []).join(" "), "qualys", v.url);
  for (const w of data("intune")?.weeks || []) {
    if (/service release/i.test(w.week)) add("Feature", `Intune ${w.week}`, "", "intune-weekly", data("intune").url);
    for (const i of w.items) add("Feature", `Intune: ${i.name}`, i.summary, "intune-weekly", i.url);
  }
  for (const i of data("intune")?.inDevelopment || []) add("Feature", `Intune in development: ${i.name}`, i.summary, "intune-dev", i.url);
  for (const i of data("mde")?.items || []) if (!out.some((o) => o.title === `Defender for Endpoint: ${i.name}`)) add("Feature", `Defender for Endpoint: ${i.name}`, i.text, "features", i.url);
  for (const i of data("roadmap")?.rows || []) add("Feature", `Roadmap: ${i.title}`, `${i.id} ${i.description}`, "roadmap", i.url);
  for (const n of data("news")?.items || []) add("News", n.title, n.summary, "news", n.url);
  for (const p of data("community")?.posts || []) add("News", `${p.community}: ${p.title}`, p.summary, "news", p.url);
  return out;
}

function renderSearch() {
  const box = document.getElementById("search-out");
  if (!box) return;
  const q = (state.searchQ || "").trim();
  if (q.length < 2 || !state.pulse) {
    box.innerHTML = "";
    return;
  }
  // Every word must match. A number must match a whole number, so "2610" does not match "4.18.26100" but "5131080" matches "KB5131080".
  const tests = q.split(/\s+/).map((w) => {
    const e = w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(/^\d+$/.test(w) ? `(^|[^0-9])${e}($|[^0-9])` : `(^|[^a-z0-9])${e}`, "i");
  });
  const hits = searchIndex().filter((x) => tests.every((t) => t.test(x.text)));
  box.innerHTML = `<div class="card"><p><strong>${hits.length} ${hits.length === 1 ? "result" : "results"}</strong> for "${esc(q)}" across CVEs, KBs, QIDs, features and news.</p>${hits.length ? `<ul class="list">${hits
    .slice(0, 30)
    .map((x) => `<li>${pill(x.kind)} <span class="row-title">${link(x.url, x.title)}</span> <a class="meta" href="#${esc(x.where)}">Go to section</a></li>`)
    .join("")}</ul>` : ""}</div>`;
}

// ---------- render + events ----------
function render() {
  renderAsOf();
  const view = document.getElementById("view");
  if (!state.pulse) {
    view.innerHTML = `<div class="notice bad">The data file did not load (${esc(state.errors.pulse || "unknown error")}). Check your connection and reload.</div>`;
    return;
  }
  const fn = { status: renderStatus, updates: renderUpdates, sense: renderSense, threats: renderThreats, intune: renderIntune, intel: renderIntel }[state.tab];
  view.innerHTML = renderAlerts() + fn();
  renderSearch();
  renderJump();
  document.querySelectorAll("#tabs a").forEach((a) => a.setAttribute("aria-current", a.dataset.tab === state.tab ? "page" : "false"));
  document.querySelectorAll("#os-chips button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.os === state.os)));
}

function route() {
  const hash = location.hash.replace("#", "");
  const tab = TABS.includes(hash) ? hash : null;
  if (tab) {
    state.tab = tab;
    render();
    window.scrollTo({ top: 0 });
    return;
  }
  // Deep link to a section: find which tab owns it.
  const owner = { "out-of-band": "updates", "si-trend": "threats", intro: "status", changes: "status", versions: "status", packages: "status", monthly: "status", compare: "status", sources: "status", "patch-tuesday": "updates", exploited: "updates", "known-issues": "updates", channels: "updates", compliance: "intune", "intune-weekly": "intune", "intune-dev": "intune", qualys: "updates", roadmap: "intune", hashes: "threats", changelog: "threats", features: "intel", chatter: "intel", sensor: "sense", "sense-issues": "sense", "sense-releases": "sense", "sense-kb": "sense", "sense-signal": "sense", "detection-alerts": "threats", "vendor-coverage": "threats", "kev-coverage": "threats", news: "intel", reddit: "intel" }[hash];
  if (owner) {
    state.tab = owner;
    render();
    scrollToSection(hash);
  } else render();
}

document.addEventListener("click", async (e) => {
  const chip = e.target.closest("#os-chips button");
  if (chip) {
    state.os = chip.dataset.os;
    pref.set("os", state.os);
    render();
    return;
  }
  const btn = e.target.closest("[data-copy]");
  if (btn) {
    try {
      await navigator.clipboard.writeText(btn.dataset.copy);
      btn.textContent = "Copied";
    } catch {
      btn.textContent = "Copy failed";
    }
    setTimeout(() => (btn.textContent = btn.dataset.label || "Copy"), 1500);
    return;
  }
  const t = e.target.closest("[data-ptmonth],[data-issue-tab],[data-roadmap],[data-feed]");
  if (t) {
    const [key, value, id] = t.dataset.ptmonth
      ? ["ptMonth", t.dataset.ptmonth, t.closest("section")?.id || "patch-tuesday"]
      : t.dataset.issueTab
        ? ["issueTab2", t.dataset.issueTab, "known-issues"]
        : t.dataset.roadmap
          ? ["roadmapMode", t.dataset.roadmap, "roadmap"]
          : ["feedFilter", t.dataset.feed, "news"];
    pref.set(key, value);
    render();
    document.querySelector(`#${id} [aria-selected="true"]`)?.focus();
    return;
  }
  const more = e.target.closest("[data-expand]");
  if (more) {
    const p = document.getElementById(more.dataset.expand);
    const open = p.classList.toggle("clamp") === false;
    more.textContent = open ? "Show less" : "Read more";
    more.setAttribute("aria-expanded", String(open));
    return;
  }
  const ex = e.target.closest("[data-export]");
  if (ex) {
    const out = exportRows();
    const json = JSON.stringify(out, null, 1);
    if (ex.dataset.export === "copy") {
      try {
        await navigator.clipboard.writeText(json);
        ex.textContent = "Copied";
      } catch {
        ex.textContent = "Copy failed";
      }
      setTimeout(() => (ex.textContent = "Copy JSON"), 1500);
      return;
    }
    const csvCell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const body = ex.dataset.export === "json" ? json : ["name,severity,change,url", ...out.rows.map((r) => [r.name, r.severity, r.change, r.url].map(csvCell).join(","))].join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([body], { type: ex.dataset.export === "json" ? "application/json" : "text/csv" }));
    a.download = `detections-${out.version}.${ex.dataset.export}`;
    document.body.append(a);
    a.click();
    setTimeout(() => (URL.revokeObjectURL(a.href), a.remove()), 1000);
    return;
  }
  const rb2 = e.target.closest('[data-action="retry-build"]');
  if (rb2) {
    const h = changelogHistory().find((x) => x.version === rb2.dataset.version);
    delete state.builds[rb2.dataset.version];
    loadBuild(h);
    return;
  }
  if (e.target.closest("#refresh-btn") || e.target.closest('[data-action="retry"]')) {
    const b = e.target.closest("button");
    b.disabled = true;
    b.textContent = "Refreshing…";
    try {
      const p = await getJson("data/pulse.json", 15000, 1);
      state.pulse = p;
      render();
    } catch {
      /* keep what is shown */
    }
    const rb = document.getElementById("refresh-btn");
    rb.disabled = false;
    rb.textContent = "Refresh data";
  }
});

document.addEventListener("input", (e) => {
  const t = e.target;
  if (t.id === "threat-q") {
    state.threatQ = t.value;
    const pos = t.selectionStart;
    rerenderChangelog();
    const n = document.getElementById("threat-q");
    n.focus();
    n.setSelectionRange(pos, pos);
    return;
  }
  if (t.id === "search-q") {
    state.searchQ = t.value;
    renderSearch();
    return;
  }
  if (t.closest("#compare-form")) {
    const f = new FormData(t.form);
    const v = { platform: String(f.get("platform")).trim(), engine: String(f.get("engine")).trim(), si: String(f.get("si")).trim() };
    pref.set("compare", { typed: true, ...Object.fromEntries(Object.entries(v).map(([k, x]) => [k, VALID_VERSION.test(x) ? x : ""])) });
    document.getElementById("compare-out").innerHTML = compareVerdict(v, data("productUpdates")?.rows || [], data("intelligence"));
  }
});

document.addEventListener("change", (e) => {
  const t = e.target;
  if (t.id === "issue-scope") pref.set("issueScope", t.value);
  else if (t.id === "si-version") {
    pref.set("siPick", { version: t.value, latest: changelogHistory()[0]?.version || "" });
    rerenderChangelog();
    return;
  } else return;
  const id = t.id;
  render();
  document.getElementById(id)?.focus();
});

document.addEventListener("submit", (e) => {
  if (e.target.id === "search-form") {
    e.preventDefault();
    return;
  }
  if (e.target.id !== "hash-form") return;
  e.preventDefault();
  const h = document.getElementById("hash-q").value.trim().toLowerCase();
  if (!/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(h)) {
    document.getElementById("hash-q").setCustomValidity("Enter an MD5, SHA-1 or SHA-256 hash");
    document.getElementById("hash-q").reportValidity();
    return;
  }
  window.open(`https://www.virustotal.com/gui/file/${h}`, "_blank", "noopener");
  window.open(`https://otx.alienvault.com/indicator/file/${h}`, "_blank", "noopener");
});
document.addEventListener("input", (e) => {
  if (e.target.id === "hash-q") e.target.setCustomValidity("");
});

window.addEventListener("hashchange", route);

state.os = pref.get("os", "all");
document.getElementById("view").innerHTML = `<div class="grid">${'<div class="skeleton"></div>'.repeat(4)}</div>`;
load().then(route);
// Pick up a new scheduled refresh without a reload.
setInterval(() => getJson("data/pulse.json", 15000, 0).then((p) => {
  if (p.checkedAt !== state.pulse?.checkedAt) {
    state.pulse = p;
    render();
  }
}).catch(() => {}), 10 * 60 * 1000);
