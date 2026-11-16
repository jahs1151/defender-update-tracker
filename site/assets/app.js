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
const CHATTER =
  /false[-\s]?positive|faulty (signature|update|detection|intelligence)|bad (signature|definition|update)|mass (detection|alert|quarantine)|detection storm|signature (revision|rollback)|reverted (signature|update)|security intelligence.{0,48}(issue|problem|false|revision)|SenseIR|MsSense|sense\.exe|impaired communication|no sensor data|sensor health|quarantin\w+ (legit|good|our|everything)/i;
const CONTROLS = /\busb\b|removable|device control|firewall|attack surface|\basr\b|bitlocker/i;
const daysOld = (iso) => (iso ? (Date.now() - Date.parse(iso)) / 86400000 : Infinity);
const size = (b) => (!b ? "" : b >= 1048576 ? `${(b / 1048576).toFixed(b >= 10485760 ? 0 : 1)} MB` : `${Math.round(b / 1024)} KB`);
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
        <td class="mono">${p.version ? esc(p.version) : na()}${p.engine ? `<div class="meta">engine ${esc(p.engine)}</div>` : ""}${p.id === "wim" && p.platform ? `<div class="meta" title="${esc(p.platformSource || "")}">platform ${esc(p.platform)}</div>` : ""}</td>
        <td>${p.lastModified ? esc(stamp(p.lastModified)) : na("Time not published")}${p.contents?.length ? `<div class="meta">Contains ${esc(p.contents.join(", "))}${p.contentsDate ? `, files dated ${esc(stamp(p.contentsDate))}` : ""}</div>` : ""}</td>
        <td>${esc(size(p.bytes))}</td>
        <td>${link(p.latestUrl, "Download x64")} · ${link(p.page, "Docs")}</td>
      </tr>`,
    )
    .join("");
  const packages = pkgs.length
    ? `<div class="card table-wrap"><table><thead><tr><th>Package</th><th>Version</th><th>File date (Last-Modified)</th><th>Size</th><th>Links</th></tr></thead><tbody>${pkgRows}</tbody></table>
       <p class="meta" style="margin-top:8px">mpam-fe.exe updates security intelligence and the engine, not the platform. updateplatform.exe updates only the platform. The offline image kit trails the daily signatures between Patch Tuesdays${(() => {
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

  const q = data("qualys");
  const qualysBody = q
    ? `<div class="card">
        <p>${esc(q.qids.length)} Qualys QIDs detect the ${esc(q.month)} Patch Tuesday fixes. Paste the query into Qualys VMDR to find unpatched hosts.</p>
        <div class="policy"><dl class="kv"><dt>Query</dt><dd><code>${esc(q.query)}</code><button type="button" class="btn small" data-copy="${esc(q.query)}">Copy</button></dd></dl></div>
        <p class="meta" style="margin-top:8px">Scraped from Qualys ThreatPROTECT, a third-party blog. Check the review if the list looks short.</p>
        ${source(q.url, "Qualys Patch Tuesday review")}
      </div>`
    : `<div class="card"><p class="meta">${esc(sec("qualys")?.detail || "Not checked yet.")} Qualys usually posts its review on Patch Tuesday evening, US time.</p></div>`;

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

  const scope = pref.get("issueScope", "security");
  const inScope = (r) => scope === "all" || (scope === "controls" ? CONTROLS.test(`${r.title} ${r.detail}`) : r.scope === "security");
  const issues = (data("knownIssues")?.rows || []).filter((r) => osOk(r.os)).filter(inScope);
  const scopeLabel = { security: "Defender, Intune or BitLocker", controls: "USB, Firewall, ASR or BitLocker", all: "Windows" }[scope];
  const issuesBody = data("knownIssues")
    ? `<div class="card">
        <div class="controls"><label class="field">Show <select id="issue-scope">
          <option value="security" ${scope === "security" ? "selected" : ""}>Defender, Intune and BitLocker issues</option>
          <option value="controls" ${scope === "controls" ? "selected" : ""}>Intune controls: USB, Firewall, ASR, BitLocker</option>
          <option value="all" ${scope === "all" ? "selected" : ""}>Every Windows known issue</option>
        </select></label></div>
        ${issues.length ? `<ul class="list">${issues
          .map((r) => `<li><span class="row-title">${link(r.url, r.title)}</span> ${pill(r.status, /resolved/i.test(r.status) ? "ok" : "warn")} ${osPills(r.os)}
            <div class="meta">${esc(r.sources.join(", "))}${r.updated ? ` · updated ${esc(stamp(r.updated))}` : ""}</div><p>${esc(r.detail)}</p></li>`)
          .join("")}</ul>` : `<p>No open or recent ${esc(scopeLabel)} known issues for this filter.</p>`}
        <p class="meta">From Windows release health. ${(data("knownIssues").pages || []).map((pg) => link(pg.url, pg.label)).join(" · ")}</p>
      </div>`
    : sectionError("knownIssues", "Windows release health");

  const channels = `<div class="card">
    <p>Defender has three separate update channel settings: engine, platform and security intelligence. Each one decides when in Microsoft's gradual rollout a device takes a new release.</p>
    <ul>
      <li><strong>Engine and platform:</strong> Beta Channel, then Current Channel (Preview), then Current Channel (Staged), then Current Channel (Broad). Critical: Time delay holds a release back further.</li>
      <li><strong>Security intelligence:</strong> Current Channel (Staged) or Current Channel (Broad). It ships several times a day.</li>
    </ul>
    <p>The public definitions page does not say which channel the current versions above are on.</p>
    ${source("https://learn.microsoft.com/en-us/defender-endpoint/manage-gradual-rollout", "Manage the gradual rollout process for Microsoft Defender updates")}
  </div>`;

  return [
    section("patch-tuesday", "Patch Tuesday", ptBody, "patchTuesday"),
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
    section("intune-weekly", "Intune weekly notes (Windows and security)", weeks, "intune"),
    section("intune-dev", "Intune in development", dev, "intune"),
    section("roadmap", "Microsoft 365 roadmap: Defender and Intune", renderRoadmap(), "roadmap"),
  ].join("");
}

function renderRoadmap() {
  const r = data("roadmap");
  if (!r) return `<div class="card"><p class="meta">${esc(sec("roadmap")?.detail || "Not checked yet.")} Microsoft's public roadmap feed is often unavailable; this section fills in when it answers.</p>${source("https://www.microsoft.com/microsoft-365/roadmap", "Microsoft 365 roadmap")}</div>`;
  return `<div class="card">${r.rows.length ? `<ul class="list">${r.rows
    .map((i) => `<li><span class="row-title">${link(i.url, i.title)}</span> ${pill(i.status || "Roadmap", /launched|rolling/i.test(i.status) ? "ok" : "")}${i.release ? ` <span class="meta">${esc(i.release)}</span>` : ""}<p>${esc(i.description)}</p></li>`)
    .join("")}</ul>` : "<p>No Defender or Intune items in the feed right now.</p>"}${source(r.url, "Microsoft 365 roadmap")}</div>`;
}

// ---------- Intel tab ----------
function renderIntel() {
  const clData = data("changelog");
  const history = clData?.history?.length ? clData.history : clData ? [clData] : [];
  const wanted = pref.get("siVersion", "");
  const cl = clData ? { ...clData, ...(history.find((h) => h.version === wanted) || history[0]) } : null;
  const winOnly = pref.get("winOnly", true);
  const isWin = (n) => !/:(Android|MacOS|OSX|Linux|iOS|Unix)\w*\//i.test(n);
  const rows = (cl?.rows || []).filter((r) => !winOnly || isWin(r.name));
  const changelog = cl
    ? `<div class="card">
        <p><strong>${esc(cl.version)}</strong> · ${cl.releasedAt ? esc(stamp(cl.releasedAt)) : na("Time not published")} · ${cl.rows.filter((r) => r.change === "added").length} added, ${cl.rows.filter((r) => r.change === "updated").length} updated</p>
        <div class="controls">
          ${history.length > 1 ? `<label class="field">Version <select id="si-version">${history.map((h, i) => `<option value="${esc(h.version)}" ${h.version === cl.version ? "selected" : ""}>${esc(h.version)}${i === 0 ? " (latest)" : ""}${h.releasedAt ? ` · ${esc(stamp(h.releasedAt).split(" · ")[0])}` : ""}</option>`).join("")}</select></label>` : ""}
          <label><input type="checkbox" id="win-only" ${winOnly ? "checked" : ""}> Hide Android, macOS and Linux detections</label>
        </div>
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

  const posts = data("community")?.posts || [];
  const chatter = [
    ...news.map((n) => ({ ...n, where: n.source })),
    ...posts.map((p) => ({ ...p, where: p.community })),
  ]
    .filter((x) => CHATTER.test(`${x.title} ${x.summary}`) && daysOld(x.published) <= 14)
    .sort((a, b) => (b.published || "").localeCompare(a.published || ""));
  const chatterBody = `<div class="card">
    <p>News and Reddit posts from the last 14 days that mention a false positive, a signature revision, a detection storm, or MsSense / SenseIR. One post is a lead. Several, plus quarantines on your pilot ring, are a reason to hold the broad ring.</p>
    ${chatter.length ? `<ul class="list">${chatter
      .slice(0, 10)
      .map((x) => `<li><span class="row-title">${link(x.url, x.title)}</span><div class="meta">${esc(x.where)} · ${x.published ? esc(stamp(x.published)) : "time not published"}</div></li>`)
      .join("")}</ul>` : `<p class="meta">Nothing matches right now. That is a real empty result, not a missing feed (see Source health).</p>`}
  </div>`;
  const redditBody = data("community")
    ? `<div class="card">${posts.length ? `<ul class="list">${posts
        .slice(0, 20)
        .map((p) => `<li><span class="row-title">${link(p.url, p.title)}</span><div class="meta">${esc(p.community)} · ${p.published ? esc(stamp(p.published)) : ""}</div>${p.summary ? `<p>${esc(p.summary)}</p>` : ""}</li>`)
        .join("")}</ul>` : "<p>No posts right now.</p>"}<p class="meta">Community posts, not Microsoft guidance. r/DefenderATP is shown in full; r/Intune and r/sysadmin only when a post mentions Defender.</p></div>`
    : sectionError("community", "Reddit");

  const hashes = data("hashes")?.rows || [];
  const short = (h) => `${h.slice(0, 12)}…${h.slice(-6)}`;
  const hashBody = `<div class="card">
    <p>SHA-256 hashes posted publicly today (TweetFeed), checked against AlienVault OTX's analysis, which includes a Microsoft Defender scan. A row marked <strong>Gap</strong> is one where another scanner names the file and Defender does not: a candidate to submit to Microsoft.</p>
    ${data("hashes") ? (hashes.length ? `<div class="table-wrap"><table><thead><tr><th>Hash</th><th>Reported</th><th>File type</th><th>Defender (OTX)</th><th>Other scanner</th><th>Links</th></tr></thead><tbody>${hashes
      .map((h) => `<tr><td class="mono" title="${esc(h.hash)}">${esc(short(h.hash))} <button type="button" class="btn small" data-copy="${esc(h.hash)}" aria-label="Copy hash">Copy</button></td>
        <td>${h.reportedAt ? esc(ago(h.reportedAt)) : ""}${h.reporter ? `<div class="meta">${esc(h.reporter)}</div>` : ""}</td>
        <td>${h.analysed ? esc(h.fileType || "unknown") : pill("Reported only")}</td>
        <td>${h.defender ? esc(h.defender) : h.analysed ? pill(h.other ? "Gap" : "Not detected", h.other ? "bad" : "") : ""}</td>
        <td>${esc(h.other || "")}</td>
        <td>${link(h.vt, "VirusTotal")} · ${link(h.otx, "OTX")}</td></tr>`)
      .join("")}</tbody></table></div>` : "<p>No Windows hashes in today's feed.</p>") : sectionError("hashes", "The public hash feed")}
    <p class="meta" style="margin-top:8px">Third-party, unvetted data. "Reported only" means OTX has no analysis yet. Use it as a lead, not as proof of a miss.</p>
    <form id="hash-form" class="controls" style="margin-top:10px">
      <label class="field" style="flex:1 1 260px">Look up a hash <input type="text" id="hash-q" placeholder="MD5, SHA-1 or SHA-256" autocomplete="off" spellcheck="false"></label>
      <button type="submit" class="btn" style="align-self:end">Open in VirusTotal and OTX</button>
    </form>
    <p class="meta">Opens the public pages in new tabs. Nothing is sent from this site.</p>
  </div>`;

  const states = [
    ["Active", "The sensor is reporting. A bad signature still shows up as alerts and quarantines, not as an inactive sensor."],
    ["Impaired communications", "The device cannot fully reach the Defender service URLs, usually because of a proxy. Isolate, live response and file submission fail until that path works."],
    ["No sensor data", "The device reaches the service but sends only partial data. Check that the Connected User Experiences and Telemetry service (DiagTrack) is running and that antivirus was not disabled by policy."],
    ["Inactive", "No signals for about seven days, or the device was offboarded. It is not a signature-version problem."],
  ];
  const sensor = `<div class="card">
    <p><strong>MsSense.exe</strong> is the Defender for Endpoint EDR sensor (service name <code>Sense</code>). It collects telemetry and sends it to the Defender portal. Its version is separate from the antivirus platform and is updated through KB5005292.</p>
    <p><strong>SenseIR.exe</strong> runs automated investigation and live response actions. It often starts PowerShell as SYSTEM, which can look alarming in process trees but is expected. Do not add allow indicators or exclusions for either file.</p>
    <p>Sensor health is in the Defender portal's device health reports, not in the antivirus signature version.</p>
    <h3 style="margin-top:12px">Sensor health states</h3>
    <div class="table-wrap"><table><thead><tr><th>State</th><th>What it means</th></tr></thead><tbody>${states.map(([a, b]) => `<tr><td><strong>${esc(a)}</strong></td><td>${esc(b)}</td></tr>`).join("")}</tbody></table></div>
    ${source("https://learn.microsoft.com/en-us/defender-endpoint/fix-unhealthy-sensors", "Fix unhealthy sensors")}
    ${source("https://learn.microsoft.com/en-us/defender-endpoint/device-health-sensor-health-os", "Device health and sensor health reports")}
  </div>`;

  return [
    section("changelog", "Detection changelog", changelog, "changelog"),
    section("features", "New Defender for Endpoint features", features + reportedBlock, "mde"),
    section("chatter", "Bad-detection chatter", chatterBody),
    section("sensor", "Sensor (MsSense / SenseIR)", sensor),
    section("news", "News", newsBody, "news"),
    section("reddit", "Reddit", redditBody, "community"),
    section("hashes", "Public hashes and Defender coverage", hashBody, "hashes"),
  ].join("");
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
  const oob = (data("news")?.items || []).filter((n) => /out-of-band|emergency (update|patch|fix)|zero-day|actively exploited/i.test(n.title) && daysOld(n.published) <= 7 && osOk(n.os));
  for (const n of oob.slice(0, 2)) alerts.push({ tone: "", html: `${esc(n.title)} (${esc(n.source)}, ${esc(ago(n.published))}). ${link(n.url, "Read")}` });
  const posts = data("community")?.posts || [];
  const recentChatter = [...(data("news")?.items || []), ...posts].filter((x) => CHATTER.test(`${x.title} ${x.summary}`) && daysOld(x.published) <= 3);
  if (recentChatter.length >= 2) alerts.push({ tone: "", html: `${recentChatter.length} posts in the last 3 days mention a possible bad detection or sensor problem. ${go("chatter", "Review before widening the broad ring")}` });
  const openIssues = (data("knownIssues")?.rows || []).filter((r) => r.scope === "security" && !/resolved/i.test(r.status) && osOk(r.os));
  for (const r of openIssues.slice(0, 2)) alerts.push({ tone: "", html: `Open known issue: ${esc(r.title)} (${esc(r.status)}). ${go("known-issues", "Known issues")}` });
  if (!alerts.length) return "";
  return `<div class="section" role="region" aria-label="Alerts">${alerts
    .slice(0, 6)
    .map((a) => `<div class="notice ${a.tone}">${a.html}</div>`)
    .join("")}</div>`;
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
  view.innerHTML = renderAlerts() + fn();
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
  const owner = { changes: "status", versions: "status", packages: "status", monthly: "status", fleet: "status", sources: "status", "patch-tuesday": "updates", exploited: "updates", "known-issues": "updates", channels: "updates", compliance: "intune", "intune-weekly": "intune", "intune-dev": "intune", qualys: "updates", roadmap: "intune", hashes: "intel", changelog: "intel", features: "intel", chatter: "intel", sensor: "intel", news: "intel", reddit: "intel" }[hash];
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

document.addEventListener("input", (e) => {
  const t = e.target;
  if (t.closest("#fleet-form")) {
    const f = new FormData(t.form);
    const v = { platform: String(f.get("platform")).trim(), engine: String(f.get("engine")).trim(), si: String(f.get("si")).trim() };
    pref.set("fleet", v);
    document.getElementById("fleet-out").innerHTML = fleetVerdict(v, data("productUpdates")?.rows || [], data("intelligence"));
  }
});

document.addEventListener("change", (e) => {
  const t = e.target;
  if (t.id === "issue-scope") pref.set("issueScope", t.value);
  else if (t.id === "win-only") pref.set("winOnly", t.checked);
  else if (t.id === "si-version") pref.set("siVersion", t.value);
  else return;
  const id = t.id;
  render();
  document.getElementById(id)?.focus();
});

document.addEventListener("submit", (e) => {
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
