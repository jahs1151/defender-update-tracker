import { stamp, ago, cmpVersion, monthsBetween } from "./time.js";

const OS = { win11: "Win 11", srv2019: "Server 2019", srv2022: "Server 2022", srv2025: "Server 2025" };
const ALL_OS = Object.keys(OS);
const TABS = ["status", "updates", "intune", "intel"];

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
const data = (key) => sec(key)?.data || null;

function checked(key) {
  const s = sec(key);
  if (!s) return "";
  const when = s.lastOkAt ? `Last good data ${ago(s.lastOkAt)}` : "No data yet";
  const tone = s.ok ? "" : s.stale ? "warn" : "bad";
  const status = s.ok ? "" : ` ${pill(s.stale ? "Stale" : "Unavailable", tone)}`;
  return `<span class="meta" title="${esc(s.detail)}">Checked ${esc(ago(s.checkedAt))} · ${esc(when)}${status}</span>`;
}

function section(id, title, body, key) {
  return `<section class="section" id="${id}" aria-labelledby="${id}-h">
    <div class="section-head"><h2 id="${id}-h">${esc(title)}</h2>${key ? checked(key) : ""}</div>
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
    getJson("data/catalog.json"),
    getJson("data/curated.json"),
    getJson("data/link-report.json", 8000, 0),
  ]);
  state.failedUrls = new Set(links.status === "fulfilled" ? links.value.failedUrls || [] : []);
  state.pulse = pulse.status === "fulfilled" ? pulse.value : null;
  state.catalog = catalog.status === "fulfilled" ? catalog.value : null;
  state.curated = curated.status === "fulfilled" ? curated.value : null;
  if (!state.pulse) state.errors.pulse = String(pulse.reason?.message || pulse.reason);
  if (!state.catalog) state.errors.catalog = String(catalog.reason?.message || catalog.reason);
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
  const live = data("sense")?.latest;
  if (live) return { version: live.version, when: live.date ? stamp(live.date) : "", note: "From the Microsoft Update Catalog (KB5005292).", url: data("sense").url };
  const f = state.curated?.senseFallback;
  if (f) return { version: f.version, when: `${stamp(f.date)} · ${f.channel}`, note: f.source, url: f.url };
  return { version: "", when: "", note: "", url: "" };
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
  return `<div class="card"><p class="meta">Detected ${esc(stamp(p.contentChangedAt))}</p><ul class="list changes">${rows}</ul></div>`;
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

  const siWhen = intel?.releasedAt ? `Released ${stamp(intel.releasedAt)}` : mpam?.lastModified ? `Package dated ${stamp(mpam.lastModified)}` : "";
  const clockNote = intel?.clockBasis ? `<p class="meta" style="margin-top:6px">${esc(intel.clockBasis)}</p>` : "";

  const cards = `<div class="grid">
    ${versionCard("Security intelligence", intel?.securityIntelligence || mpam?.version, siWhen, intel?.url || "https://www.microsoft.com/en-us/wdsi/definitions", clockNote)}
    ${versionCard("Engine", intel?.engine || mpam?.engine, engRelease?.released ? `Monthly release ${stamp(engRelease.released)}` : "Ships with security intelligence", intel?.url)}
    ${versionCard("Platform", intel?.platform || plat?.version, platRelease?.released ? `Monthly release ${stamp(platRelease.released)}` : plat?.lastModified ? `Package dated ${stamp(plat.lastModified)}` : "", "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates")}
    ${versionCard("Sense (MsSense.exe)", sense.version, sense.when, sense.url, sense.note ? `<p class="meta" style="margin-top:6px">${esc(sense.note)}</p>` : "")}
  </div>`;

  const pkgRows = pkgs
    .map(
      (p) => `<tr>
        <td><div class="row-title">${esc(p.name)}</div><div class="meta">${esc(p.file)}${p.kb ? ` · ${esc(p.kb)}` : ""}</div></td>
        <td class="mono">${p.version ? esc(p.version) : na()}${p.engine ? `<div class="meta">engine ${esc(p.engine)}</div>` : ""}</td>
        <td>${p.lastModified ? esc(stamp(p.lastModified)) : na("Time not published")}</td>
        <td>${link(p.latestUrl, "Download x64")} · ${link(p.page, "Docs")}</td>
      </tr>`,
    )
    .join("");
  const packages = pkgs.length
    ? `<div class="card table-wrap"><table><thead><tr><th>Package</th><th>Version</th><th>File date (Last-Modified)</th><th>Links</th></tr></thead><tbody>${pkgRows}</tbody></table>
       <p class="meta" style="margin-top:8px">mpam-fe.exe updates security intelligence and the engine, not the platform. updateplatform.exe updates only the platform. The offline image kit trails the daily signatures between Patch Tuesdays.</p></div>`
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
  const relRows = releases
    .map((r) => `<tr><td>${esc(r.label)}</td><td class="mono">${esc(r.platform)}</td><td class="mono">${esc(r.engine)}</td><td>${r.released ? esc(stamp(r.released)) : na("Not published")}</td><td>${support(r.platform)}</td></tr>`)
    .join("");
  const releaseTable = `<div class="card">
      <p>Microsoft supports the current platform and engine plus the two monthly releases before them (N-2). Older clients stop receiving security intelligence. Defender versions carry their build month (4.18.<strong>2610</strong>0.x is an October 2026 build), so this site estimates N-2 from that month code against the current platform ${currentPlatform ? `<code>${esc(currentPlatform)}</code>` : ""}.</p>
      ${lag != null && lag > 2 ? `<div class="notice">Microsoft's release-notes page currently lists releases only up to ${esc(latestListed.label)}, ${lag} months behind the current platform. Use the month-code estimate and Fleet compare for recent builds.</div>` : ""}
      ${releases.length ? `<div class="table-wrap"><table><thead><tr><th>Release notes entry</th><th>Platform</th><th>Engine</th><th>Released</th><th>Support today</th></tr></thead><tbody>${relRows}</tbody></table></div>` : sectionError("productUpdates", "The monthly release notes")}
      ${source("https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates", "Microsoft Defender Antivirus security intelligence and product updates")}
      ${source(data("productUpdates")?.url, "Monthly platform and engine release notes")}
    </div>`;

  const sources = Object.entries(state.pulse.sections)
    .map(([, s]) => `<li><span class="row-title">${esc(s.label)}</span> ${s.ok ? pill("OK", "ok") : s.stale ? pill("Stale", "warn") : pill("Failed", "bad")}<div class="meta">${esc(s.detail)}</div></li>`)
    .join("");

  return [
    section("changes", "What changed since the last refresh", renderChanges()),
    section("versions", "Current Defender versions", cards, "intelligence"),
    section("packages", "Download packages", packages, "packages"),
    section("monthly", "Monthly platform and engine releases (N-2)", releaseTable, "productUpdates"),
    section("fleet", "Fleet compare", renderFleet(releases, intel)),
    section("sources", "Source health", `<div class="card"><ul class="list">${sources}</ul></div>`),
  ].join("");
}

function renderFleet(releases, intel) {
  const saved = pref.get("fleet", { platform: "", engine: "", si: "" });
  return `<div class="card">
    <p>Paste versions from a device (Get-MpComputerStatus: AMProductVersion, AMEngineVersion, AntivirusSignatureVersion). Saved only in this browser.</p>
    <form class="form-grid" id="fleet-form" autocomplete="off">
      <label class="field">Platform <input type="text" name="platform" inputmode="decimal" placeholder="4.18.xxxxx.x" value="${esc(saved.platform)}"></label>
      <label class="field">Engine <input type="text" name="engine" inputmode="decimal" placeholder="1.1.xxxxx.x" value="${esc(saved.engine)}"></label>
      <label class="field">Security intelligence <input type="text" name="si" inputmode="decimal" placeholder="1.4xx.xxx.0" value="${esc(saved.si)}"></label>
    </form>
    <div id="fleet-out" aria-live="polite" style="margin-top:10px">${fleetVerdict(saved, releases, intel)}</div>
  </div>`;
}

function fleetVerdict(v, releases, intel) {
  const out = [];
  const rank = (value, current) => {
    if (!value) return "";
    if (!current) return pill("Current version not known yet", "warn");
    if (cmpVersion(value, current) >= 0) return pill("Current (N)", "ok");
    const gap = monthsBetween(current, value);
    if (gap == null) return pill("Unrecognised version format", "warn");
    if (gap <= 2) return pill(`Supported (about N-${Math.max(gap, 1)})`, "ok");
    return pill(`About ${gap} months old: older than N-2, update it`, "bad");
  };
  if (v.platform) out.push(`<li>Platform <code>${esc(v.platform)}</code> ${rank(v.platform, intel?.platform)}</li>`);
  if (v.engine) out.push(`<li>Engine <code>${esc(v.engine)}</code> ${rank(v.engine, intel?.engine)}</li>`);
  if (v.si && intel?.securityIntelligence) {
    const d = cmpVersion(intel.securityIntelligence, v.si);
    out.push(`<li>Security intelligence <code>${esc(v.si)}</code> ${d <= 0 ? pill("Current", "ok") : pill(`Behind the current ${intel.securityIntelligence}`, "warn")}</li>`);
  }
  return out.length ? `<ul class="list">${out.join("")}</ul><p class="meta">Platform and engine support is estimated from the build month in the version number.</p>` : `<p class="meta">Enter a version to compare.</p>`;
}

// ---------- Updates tab ----------
function renderUpdates() {
  const pt = data("patchTuesday");
  const p = state.pulse.patch;
  const ptBody = pt
    ? `<div class="grid">
        <div class="card"><div class="kpi-label">Release</div><div class="kpi">${esc(pt.month)}</div><div class="when">Last Patch Tuesday ${esc(stamp(p.last))}. Next ${esc(stamp(p.next))}.</div>${source(pt.url, "Security Update Guide")}</div>
        <div class="card"><div class="kpi-label">Windows CVEs (in-scope versions)</div><div class="kpi">${esc(pt.windowsTotal)}</div><div class="when">${esc(pt.critical)} rated Critical</div></div>
        <div class="card"><div class="kpi-label">Defender or Intune CVEs</div><div class="kpi">${esc(pt.endpoint.length)}</div><div class="when">${pt.endpoint.length ? "Listed below" : "None this month"}</div></div>
      </div>
      <div class="card table-wrap" style="margin-top:12px"><table><thead><tr><th>Operating system</th><th>CVEs</th><th>Critical</th></tr></thead><tbody>${Object.entries(pt.perOs || {})
        .sort(([a], [b]) => ALL_OS.indexOf(a) - ALL_OS.indexOf(b))
        .filter(([os]) => state.os === "all" || os === state.os)
        .map(([os, c]) => `<tr><td>${esc(OS[os] || os)}</td><td>${esc(c.total)}</td><td>${esc(c.critical)}</td></tr>`)
        .join("")}</tbody></table><p class="meta" style="margin-top:6px">Windows 11 counts 24H2 and 25H2 together. Counts include CVEs Microsoft added to the release after Patch Tuesday.</p></div>
      ${pt.endpoint.length ? `<div class="card table-wrap" style="margin-top:12px"><table><thead><tr><th>CVE</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Released</th></tr></thead><tbody>${pt.endpoint
        .map((r) => `<tr><td>${link(r.url, r.cve)}</td><td>${esc(r.title)}</td><td>${esc(r.severity)}</td><td>${esc(r.score)}</td><td>${r.released ? esc(stamp(r.released)) : na("Time not published")}</td></tr>`)
        .join("")}</tbody></table></div>` : ""}`
    : `${sectionError("patchTuesday", "The Security Update Guide")}<div class="card"><p>Last Patch Tuesday ${esc(stamp(p.last))}. Next ${esc(stamp(p.next))}.</p></div>`;

  const kev = (data("kev")?.rows || []).filter((r) => osOk(r.os));
  // Hand-kept entries whose link failed the weekly check are hidden until fixed.
  const incidents = (state.curated?.incidents || []).filter((i) => !state.failedUrls?.has(i.url));
  const kevBody = `<div class="card">
    ${incidents.length ? `<h3>Defender exploits tracked by hand</h3><ul class="list" style="margin-bottom:14px">${incidents
      .map((i) => `<li><span class="row-title">${link(i.url, i.name)}</span> ${pill(i.status, i.status === "Patched" ? "ok" : "warn")}<div class="meta">${esc(stamp(i.date))}</div><p>${esc(i.summary)}</p></li>`)
      .join("")}</ul>` : ""}
    <h3>CISA Known Exploited Vulnerabilities, Microsoft Windows and endpoint, last 12 months</h3>
    ${kev.length ? `<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Name</th><th>Added</th><th>Due</th></tr></thead><tbody>${kev
      .slice(0, 25)
      .map((r) => `<tr><td>${link(r.url, r.cve)}${r.endpointSecurity ? ` ${pill("Defender/Intune", "bad")}` : ""}</td><td>${esc(r.name)}${r.ransomware === "Known" ? ` ${pill("Ransomware", "bad")}` : ""}</td><td>${esc(stamp(r.dateAdded))}</td><td>${r.dueDate ? esc(stamp(r.dueDate)) : ""}</td></tr>`)
      .join("")}</tbody></table></div>` : data("kev") ? `<p>No entries match this filter.</p>` : sectionError("kev", "The CISA catalog")}
    ${source(data("kev")?.url, "CISA catalog")}
  </div>`;

  const showAll = pref.get("issuesAll", false);
  const issues = (data("knownIssues")?.rows || []).filter((r) => osOk(r.os)).filter((r) => showAll || r.scope === "security");
  const issuesBody = data("knownIssues")
    ? `<div class="card">
        <div class="controls"><label><input type="checkbox" id="issues-all" ${showAll ? "checked" : ""}> Show every Windows issue, not only Defender, Intune and BitLocker</label></div>
        ${issues.length ? `<ul class="list">${issues
          .map((r) => `<li><span class="row-title">${link(r.url, r.title)}</span> ${pill(r.status, /resolved/i.test(r.status) ? "ok" : "warn")} ${osPills(r.os)}
            <div class="meta">${esc(r.sources.join(", "))}${r.updated ? ` · updated ${esc(stamp(r.updated))}` : ""}</div><p>${esc(r.detail)}</p></li>`)
          .join("")}</ul>` : `<p>No ${showAll ? "" : "Defender, Intune or BitLocker "}known issues for this filter.</p>`}
        <p class="meta">From Windows release health. ${(data("knownIssues").pages || []).map((pg) => link(pg.url, pg.label)).join(" · ")}</p>
      </div>`
    : sectionError("knownIssues", "Windows release health");

  const channels = `<div class="card">
    <p>Defender has three separate update channel settings: engine, platform and security intelligence. Each one decides when in Microsoft's gradual rollout a device takes a new release.</p>
    <div class="table-wrap"><table><thead><tr><th>Setting (Defender CSP)</th><th>Channels</th></tr></thead><tbody>
      <tr><td><code>./Vendor/MSFT/Defender/Configuration/EngineUpdatesChannel</code></td><td>Not configured (default), Beta Channel, Current Channel (Preview), Current Channel (Staged), Current Channel (Broad), Critical: Time delay</td></tr>
      <tr><td><code>./Vendor/MSFT/Defender/Configuration/PlatformUpdatesChannel</code></td><td>Not configured (default), Beta Channel, Current Channel (Preview), Current Channel (Staged), Current Channel (Broad), Critical: Time delay</td></tr>
      <tr><td><code>./Vendor/MSFT/Defender/Configuration/SecurityIntelligenceUpdatesChannel</code></td><td>Not configured (default), Current Channel (Staged), Current Channel (Broad)</td></tr>
    </tbody></table></div>
    <p style="margin-top:10px">The supported way to stage updates is a pilot group on Current Channel (Staged) and the rest of the fleet on Current Channel (Broad). Critical: Time delay holds engine and platform releases back further, for devices that must change last. Exact values and Intune paths are in the <a href="#catalog">policy catalog</a> under "Update rings, signatures and incident response".</p>
    ${source("https://learn.microsoft.com/en-us/defender-endpoint/manage-gradual-rollout", "Manage the gradual rollout process for Microsoft Defender updates")}
  </div>`;

  return [
    section("patch-tuesday", "Patch Tuesday", ptBody, "patchTuesday"),
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
      <li><strong>Microsoft Defender Antimalware minimum version</strong>: the lowest allowed Defender client version, for example 4.18.xxxx.x. Set it to the N-2 platform from the Status tab so devices on supported builds stay compliant.</li>
    </ul>
    <p><strong>Require BitLocker</strong> is read through Device Health Attestation, which is measured at boot. A device that finishes encrypting only reports compliant after its next restart. After a BIOS or firmware update, BitLocker can be suspended until it is resumed, which shows as non-compliant. That is not an antivirus failure.</p>
    <p>This site cannot see your tenant, policies or devices.</p>
    ${source("https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-create-windows", "Windows compliance settings in Intune")}
  </div>`;

  const intune = data("intune");
  const weeks = intune
    ? `<div class="card">${intune.weeks
        .slice(0, 6)
        .map((w) => `<h3>${esc(w.week)}</h3>${w.items.length ? `<ul class="list" style="margin-bottom:12px">${w.items.map((i) => `<li><span class="row-title">${link(i.url, i.name)}</span><p>${esc(i.summary)}</p></li>`).join("")}</ul>` : `<p class="meta">No Windows or security items this week.</p>`}`)
        .join("")}${source(intune.url, "Intune what's new")}</div>`
    : sectionError("intune", "Intune what's new");
  const dev = intune?.inDevelopment?.length
    ? `<div class="card"><ul class="list">${intune.inDevelopment.map((i) => `<li><span class="row-title">${esc(i.name)}</span><p>${esc(i.summary)}</p></li>`).join("")}</ul>${source(intune.inDevelopmentUrl, "In development for Intune")}</div>`
    : `<div class="card"><p>${intune ? "No Windows or security items, or the page could not be read." : "Not available yet."}</p>${source("https://learn.microsoft.com/en-us/intune/whats-new/in-development", "In development for Intune")}</div>`;

  return [
    section("compliance", "Intune compliance: antivirus, versions and BitLocker", compliance),
    section("catalog", "Policy catalog (OMA-URI and settings catalog)", renderCatalog()),
    section("asr", "ASR rule value builder", renderAsr()),
    section("intune-weekly", "Intune weekly notes (Windows and security)", weeks, "intune"),
    section("intune-dev", "Intune in development", dev, "intune"),
  ].join("");
}

function renderCatalog() {
  const c = state.catalog;
  if (!c) return `<div class="notice">The policy catalog did not load. ${esc(state.errors.catalog || "")}</div>`;
  const area = pref.get("area", "all");
  const q = pref.get("q", "");
  const areas = Object.entries(c.areaLabels);
  const items = c.policies
    .filter((p) => osOk(p.os))
    .filter((p) => area === "all" || p.area === area)
    .filter((p) => !q || `${p.name} ${p.summary} ${p.omaUri} ${p.note}`.toLowerCase().includes(q.toLowerCase()));
  const copy = (text) => `<button type="button" class="btn small" data-copy="${esc(text)}" aria-label="Copy ${esc(text.slice(0, 40))}">Copy</button>`;
  const uri = (p) => {
    const list = p.omaUris || [p.omaUri];
    return list.map((u) => `<dd>${/^\.\//.test(u) ? `<code>${esc(u)}</code>${copy(u)}` : esc(u)}</dd>`).join("");
  };
  return `<div class="controls">
      <label class="field" style="flex:1 1 220px">Search <input type="search" id="cat-q" value="${esc(q)}" placeholder="Name, OMA-URI or note"></label>
      <label class="field">Area <select id="cat-area"><option value="all">All areas</option>${areas.map(([k, v]) => `<option value="${k}" ${k === area ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>
    </div>
    <p class="meta">${items.length} of ${c.policies.length} items. ADMX-backed settings take a String value such as <code>&lt;enabled/&gt;&lt;data id="…" value="…"/&gt;</code>, not an Integer.</p>
    <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(min(340px,100%),1fr))">${items
      .map(
        (p) => `<article class="card policy">
          <div><span class="pill">${esc(c.areaLabels[p.area] || p.area)}</span> ${p.primary ? pill("Recommended", "ok") : ""}${p.extra ? pill("Extra option") : ""} ${osPills(p.os)}</div>
          <h3>${esc(p.name)}</h3>
          ${p.warning ? `<div class="notice bad">${esc(p.warning)}</div>` : ""}
          <p>${esc(p.summary)}</p>
          <dl class="kv">
            <dt>Intune</dt><dd>${esc(p.intunePath)}</dd>
            <dt>OMA-URI</dt>${uri(p)}
            <dt>Type</dt><dd>${esc(p.dataType)}</dd>
            <dt>Value</dt><dd><code>${esc(p.value)}</code>${copy(p.value)}</dd>
          </dl>
          ${p.note ? `<p class="meta">${esc(p.note)}</p>` : ""}
          ${source(p.docs, "Microsoft Learn")}
        </article>`,
      )
      .join("")}</div>`;
}

function renderAsr() {
  const c = state.catalog;
  if (!c) return "";
  const modes = pref.get("asr", {});
  const rules = c.asr.filter((r) => osOk(r.os));
  const value = c.asr
    .filter((r) => modes[r.guid] !== undefined && modes[r.guid] !== "")
    .map((r) => `${r.guid}=${modes[r.guid]}`)
    .join("|");
  return `<div class="card">
    <p>Pick a mode per rule. The value goes in <code>${esc(c.asrOma)}</code> as a String. Rules left blank are not configured. Modes: 0 Off, 1 Block, 2 Audit, 6 Warn.</p>
    <div class="table-wrap"><table><thead><tr><th>Rule</th><th>Mode</th></tr></thead><tbody>${rules
      .map(
        (r) => `<tr><td>${esc(r.name)} ${r.standard ? pill("Standard protection", "ok") : ""}<div class="meta mono">${esc(r.guid)}</div>${r.note ? `<div class="meta">${esc(r.note)}</div>` : ""}</td>
        <td><select data-asr="${esc(r.guid)}" aria-label="Mode for ${esc(r.name)}"><option value="">Not configured</option>${c.asrModes
          .map((m) => `<option value="${m.id}" ${String(modes[r.guid]) === String(m.id) ? "selected" : ""}>${esc(m.label)}</option>`)
          .join("")}</select></td></tr>`,
      )
      .join("")}</tbody></table></div>
    <p style="margin-top:10px"><strong>Value</strong></p>
    <div class="policy"><dl class="kv"><dt>String</dt><dd><code id="asr-value">${value ? esc(value) : "Choose at least one rule"}</code>${value ? `<button type="button" class="btn small" data-copy="${esc(value)}">Copy</button>` : ""}</dd></dl></div>
    ${source("https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference", "ASR rules reference")}
  </div>`;
}

// ---------- Intel tab ----------
function renderIntel() {
  const cl = data("changelog");
  const winOnly = pref.get("winOnly", true);
  const isWin = (n) => !/:(Android|MacOS|OSX|Linux|iOS|Unix)\//i.test(n);
  const rows = (cl?.rows || []).filter((r) => !winOnly || isWin(r.name));
  const changelog = cl
    ? `<div class="card">
        <p><strong>${esc(cl.version)}</strong> · ${cl.releasedAt ? esc(stamp(cl.releasedAt)) : na("Time not published")} · ${cl.rows.filter((r) => r.change === "added").length} added, ${cl.rows.filter((r) => r.change === "updated").length} updated</p>
        <div class="controls"><label><input type="checkbox" id="win-only" ${winOnly ? "checked" : ""}> Hide Android, macOS and Linux detections</label></div>
        <div class="table-wrap"><table><thead><tr><th>Detection</th><th>Severity</th><th>Change</th></tr></thead><tbody>${rows
          .slice(0, 60)
          .map((r) => `<tr><td>${link(r.url, r.name)}</td><td>${esc(r.severity)}</td><td>${esc(r.change)}</td></tr>`)
          .join("")}</tbody></table></div>
        ${source(cl.url, "Security intelligence release notes")}
      </div>`
    : sectionError("changelog", "The detection changelog");

  const mde = data("mde");
  const features = mde
    ? `<div class="card"><ul class="list">${mde.items
        .slice(0, 20)
        .map((i) => `<li><span class="row-title">${link(i.url, i.name)}</span> ${pill(i.stage, i.stage === "GA" ? "ok" : "")} <span class="meta">${esc(i.when)} · ${esc(i.type)}</span><p>${esc(i.text)}</p></li>`)
        .join("")}</ul>${source(mde.url, "What's new in Defender for Endpoint")}</div>`
    : sectionError("mde", "Defender for Endpoint what's new");
  const reported = (state.catalog?.features || []).filter((f) => f.status === "Reported");
  const reportedBlock = reported.length
    ? `<div class="card" style="margin-top:12px"><h3>Reported, not yet confirmed on Microsoft Learn</h3><ul class="list">${reported
        .map((f) => `<li><span class="row-title">${esc(f.name)}</span> ${pill("Reported", "warn")}<p>${esc(f.summary)}</p>${source(f.docs)}</li>`)
        .join("")}</ul></div>`
    : "";

  const news = (data("news")?.items || []).filter((n) => osOk(n.os));
  const newsBody = data("news")
    ? `<div class="card">${news.length ? `<ul class="list">${news
        .slice(0, 30)
        .map((n) => `<li><span class="row-title">${link(n.url, n.title)}</span><div class="meta">${esc(n.source)} · ${n.published ? esc(stamp(n.published)) : "time not published"}</div>${n.summary ? `<p>${esc(n.summary)}</p>` : ""}</li>`)
        .join("")}</ul>` : "<p>No headlines match this filter.</p>"}</div>`
    : sectionError("news", "The news feeds");

  const sensor = `<div class="card">
    <p><strong>MsSense.exe</strong> is the Defender for Endpoint EDR sensor (service name <code>Sense</code>). It collects telemetry and sends it to the Defender portal. Its version is separate from the antivirus platform and is updated through KB5005292.</p>
    <p><strong>SenseIR.exe</strong> runs automated investigation and live response actions. It often starts PowerShell as SYSTEM, which can look alarming in process trees but is expected. Do not add allow indicators or exclusions for either file.</p>
    <p>Sensor health is in the Defender portal's device health reports, not in the antivirus signature version.</p>
    ${source("https://learn.microsoft.com/en-us/defender-endpoint/device-health-sensor-health-os", "Device health and sensor health reports")}
  </div>`;

  return [
    section("changelog", "Detection changelog", changelog, "changelog"),
    section("features", "New Defender for Endpoint features", features + reportedBlock, "mde"),
    section("sensor", "Sensor (MsSense / SenseIR)", sensor),
    section("news", "News", newsBody, "news"),
  ].join("");
}

// ---------- render + events ----------
function render() {
  renderAsOf();
  const view = document.getElementById("view");
  if (!state.pulse) {
    view.innerHTML = `<div class="notice bad">The data file did not load (${esc(state.errors.pulse || "unknown error")}). Check your connection and reload.</div>`;
    return;
  }
  const fn = { status: renderStatus, updates: renderUpdates, intune: renderIntune, intel: renderIntel }[state.tab];
  view.innerHTML = fn();
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
  const owner = { changes: "status", versions: "status", packages: "status", monthly: "status", fleet: "status", sources: "status", "patch-tuesday": "updates", exploited: "updates", "known-issues": "updates", channels: "updates", compliance: "intune", catalog: "intune", asr: "intune", "intune-weekly": "intune", "intune-dev": "intune", changelog: "intel", features: "intel", sensor: "intel", news: "intel" }[hash];
  if (owner) {
    state.tab = owner;
    render();
    document.getElementById(hash)?.scrollIntoView();
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
    setTimeout(() => (btn.textContent = "Copy"), 1500);
  }
});

let typing;
document.addEventListener("input", (e) => {
  const t = e.target;
  if (t.closest("#fleet-form")) {
    const f = new FormData(t.form);
    const v = { platform: String(f.get("platform")).trim(), engine: String(f.get("engine")).trim(), si: String(f.get("si")).trim() };
    pref.set("fleet", v);
    document.getElementById("fleet-out").innerHTML = fleetVerdict(v, data("productUpdates")?.rows || [], data("intelligence"));
  } else if (t.id === "cat-q") {
    clearTimeout(typing);
    typing = setTimeout(() => {
      pref.set("q", t.value);
      const pos = t.selectionStart;
      render();
      const again = document.getElementById("cat-q");
      again.focus();
      again.setSelectionRange(pos, pos);
    }, 250);
  }
});

document.addEventListener("change", (e) => {
  const t = e.target;
  if (t.id === "cat-area") pref.set("area", t.value);
  else if (t.id === "issues-all") pref.set("issuesAll", t.checked);
  else if (t.id === "win-only") pref.set("winOnly", t.checked);
  else if (t.dataset.asr) {
    const m = pref.get("asr", {});
    if (t.value === "") delete m[t.dataset.asr];
    else m[t.dataset.asr] = Number(t.value);
    pref.set("asr", m);
  } else return;
  const id = t.id;
  const asr = t.dataset.asr;
  render();
  (id ? document.getElementById(id) : document.querySelector(`[data-asr="${asr}"]`))?.focus();
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
