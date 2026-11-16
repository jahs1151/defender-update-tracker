// Network loaders. Each returns { ok, detail, data } and never throws.
import { getText, getJson, resolveDownload, errorText } from "./http.mjs";
import * as P from "./parsers.mjs";
import { toIso, osTags } from "./text.mjs";
import { secondTuesday } from "../../site/assets/time.js";
import { exeContents, wimPlatform } from "./packages.mjs";

export const URLS = {
  definitions: "https://www.microsoft.com/en-us/wdsi/definitions",
  changelog: "https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes",
  productUpdates: "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates",
  monthlyReleases: "https://learn.microsoft.com/en-us/defender-endpoint/msda-updates-previous-versions-technical-upgrade-support",
  wimPage:
    "https://support.microsoft.com/en-us/servicing/management-tools/microsoft-defender/update/microsoft-defender-update-for-windows-operating-system-installation-images",
  mdeWhatsNew: "https://learn.microsoft.com/en-us/defender-endpoint/whats-new-in-microsoft-defender-endpoint",
  intuneWhatsNew: "https://learn.microsoft.com/en-us/intune/whats-new/",
  intuneInDev: "https://learn.microsoft.com/en-us/intune/whats-new/in-development",
  kev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  senseCatalog: "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5005292",
};

const ok = (detail, data) => ({ ok: true, detail, data });
const fail = (error) => ({ ok: false, detail: errorText(error), data: null });

const PACKAGES = [
  { id: "mpam-fe", name: "Security intelligence package", file: "mpam-fe.exe", kb: "KB2267602", latestUrl: "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64", page: URLS.definitions },
  { id: "updateplatform", name: "Antimalware platform package", file: "updateplatform.exe", kb: "KB4052623", latestUrl: "https://go.microsoft.com/fwlink/?LinkID=870379&arch=x64", page: URLS.productUpdates },
  { id: "wim", name: "Offline image (WIM/VHD) update kit", file: "defender-update-kit-x64.zip", kb: "", latestUrl: "https://go.microsoft.com/fwlink/?linkid=2144531", page: URLS.wimPage },
];

export async function loadPackages() {
  const wimPage = await getText(URLS.wimPage).then(P.parseWimPage).catch(() => null);
  const results = await Promise.all(
    PACKAGES.map(async (spec) => {
      try {
        const target = await resolveDownload(spec.latestUrl);
        const { packageVersion, engineVersion } = P.parseDownloadUrl(target.url);
        const row = {
          ...spec,
          version: packageVersion,
          engine: engineVersion,
          platform: spec.id === "updateplatform" ? packageVersion : "",
          lastModified: toIso(target.lastModified),
          bytes: target.bytes,
          downloadUrl: target.url.toString(),
          contents: [],
          contentsDate: "",
          error: packageVersion ? "" : "Version missing from the download redirect",
        };
        if (spec.id === "wim") {
          row.engine = wimPage?.engine || "";
          row.platform = wimPage?.platform || "";
          row.securityIntelligence = wimPage?.securityIntelligence || packageVersion;
          const fromCab = await wimPlatform(row.downloadUrl, row.bytes).catch(() => "");
          if (fromCab) {
            row.platform = fromCab;
            row.platformSource = "Read from the platform folder inside defender-dism-x64.cab";
          } else if (row.platform) {
            row.platformSource = "As listed on Microsoft's offline image page";
          }
        } else {
          const facts = await exeContents(row.downloadUrl).catch(() => null);
          if (facts) {
            row.contents = facts.files;
            row.contentsDate = facts.fileDate;
          }
        }
        return row;
      } catch (error) {
        return { ...spec, version: "", engine: "", lastModified: "", bytes: 0, downloadUrl: spec.latestUrl, contents: [], error: errorText(error) };
      }
    }),
  );
  const good = results.filter((r) => r.version);
  if (!good.length) return { ok: false, detail: results.map((r) => `${r.file}: ${r.error}`).join("; "), data: null };
  const lists = results.filter((r) => r.contents?.length).length;
  const wim = results.find((r) => r.id === "wim");
  return ok(
    `${good.length} of ${results.length} packages resolved · file lists for ${lists} · offline kit platform ${wim?.platform || "not found"}${wimPage ? "" : " (offline image page not read)"}`,
    results,
  );
}

const SUBREDDITS = [
  { sub: "DefenderATP", filter: false },
  { sub: "Intune", filter: true },
  { sub: "sysadmin", filter: true },
];

export async function loadCommunity() {
  const packs = [];
  for (const { sub, filter } of SUBREDDITS) {
    try {
      const q = new URLSearchParams({ subreddit: sub, limit: "40", sort: "desc" });
      const url = `https://arctic-shift.photon-reddit.com/api/posts/search?${q}`;
      // Arctic Shift rate-limits bursts: one slow retry before giving up on a subreddit.
      const json = await getJson(url, { timeoutMs: 20000, retries: 1 }).catch(async () => {
        await new Promise((r) => setTimeout(r, 6000));
        return getJson(url, { timeoutMs: 25000, retries: 1 });
      });
      packs.push({ sub, ok: true, posts: P.parseRedditPosts(json, sub, filter) });
    } catch (error) {
      packs.push({ sub, ok: false, posts: [], error: errorText(error) });
    }
    await new Promise((r) => setTimeout(r, 2500));
  }
  if (!packs.some((p) => p.ok)) return { ok: false, detail: packs.map((p) => `r/${p.sub}: ${p.error}`).join("; "), data: null };
  const posts = packs.flatMap((p) => p.posts).sort((a, b) => (b.published || "").localeCompare(a.published || "")).slice(0, 30);
  const failed = packs.filter((p) => !p.ok).map((p) => `r/${p.sub}`);
  return ok(`${posts.length} posts${failed.length ? ` (failed: ${failed.join(", ")})` : ""}`, { posts, subs: packs.map((p) => ({ sub: p.sub, ok: p.ok })) });
}

export async function loadIntelligence(packages) {
  try {
    const parsed = P.parseDefinitions(await getText(URLS.definitions));
    if (!parsed) throw new Error("Version block not found on the page");
    const mpam = (packages || []).find((p) => p.id === "mpam-fe");
    const sameVersion = mpam && mpam.version === parsed.securityIntelligence;
    const clock = P.resolveDefinitionsClock(parsed.releasedRaw, parsed.zoneLabel, sameVersion ? mpam.lastModified : "");
    return ok(`${parsed.securityIntelligence} · engine ${parsed.engine} · platform ${parsed.platform}`, {
      securityIntelligence: parsed.securityIntelligence,
      engine: parsed.engine,
      platform: parsed.platform,
      releasedAt: clock.releasedAt,
      releasedRaw: parsed.releasedRaw,
      clockZone: clock.zone,
      clockBasis: clock.basis,
      url: URLS.definitions,
    });
  } catch (error) {
    return fail(error);
  }
}

export async function loadProductUpdates() {
  try {
    const rows = P.parseProductUpdates(await getText(URLS.monthlyReleases));
    if (!rows.length) throw new Error("No platform/engine releases found");
    return ok(`${rows.length} monthly releases listed, latest ${rows[0].label}`, { rows, url: URLS.monthlyReleases });
  } catch (error) {
    return fail(error);
  }
}

export async function loadChangelog() {
  try {
    const parsed = P.parseChangelog(await getText(URLS.changelog));
    if (!parsed.version) throw new Error("No version on the changelog page");
    // Earlier versions: the page takes ?requestVersion=. Keep the last 10 including the current one.
    const older = parsed.versions.filter((v) => v !== parsed.version).slice(0, 9);
    const history = [{ version: parsed.version, releasedRaw: parsed.releasedRaw, rows: parsed.rows.slice(0, 120) }];
    for (const v of older) {
      try {
        const p = P.parseChangelog(await getText(`${URLS.changelog}?requestVersion=${encodeURIComponent(v)}`, { retries: 1 }));
        history.push({ version: p.version || v, releasedRaw: p.releasedRaw, rows: p.rows.slice(0, 120) });
      } catch {
        /* one missing version is fine */
      }
    }
    // The changelog clock is the same as the definitions clock; the collector converts it.
    return ok(`${parsed.version} · ${parsed.rows.length} detections · ${history.length} versions kept`, {
      ...parsed,
      rows: parsed.rows.slice(0, 120),
      history,
      url: URLS.changelog,
    });
  } catch (error) {
    return fail(error);
  }
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const releaseNumber = (d) => `${d.getUTCFullYear()}-${MONTHS[d.getUTCMonth()]}`;

const SUG = "https://api.msrc.microsoft.com/sug/v2.0/en-US";

async function sugAll(entity, filter, maxPages = 6) {
  const rows = [];
  let url = `${SUG}/${entity}?${new URLSearchParams({ $filter: filter, $top: "500" })}`;
  for (let page = 0; page < maxPages && url; page += 1) {
    const json = await getJson(url, { timeoutMs: 30000 });
    rows.push(...(json.value || []));
    url = json["@odata.nextLink"] || "";
  }
  return rows;
}

const OS_PRODUCTS = {
  win11: ["Windows 11 Version 25H2 for x64-based Systems", "Windows 11 Version 24H2 for x64-based Systems"],
  srv2025: ["Windows Server 2025"],
  srv2022: ["Windows Server 2022"],
  srv2019: ["Windows Server 2019"],
};

export async function loadPatchTuesday(now = new Date(), previous = null) {
  try {
    // Before this month's Patch Tuesday, the latest Windows release is last month's.
    const thisPt = secondTuesday(now.getUTCFullYear(), now.getUTCMonth());
    const ref = now.getTime() >= thisPt.getTime() + 17 * 3600000 ? now : new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
    const month = releaseNumber(ref);
    const prevMonth = releaseNumber(new Date(Date.UTC(ref.getUTCFullYear(), ref.getUTCMonth() - 1, 1)));
    const current = await summarizeMonth(month);
    // The month before: kept from the last snapshot, fetched once if missing. Lets the page switch months.
    const months = {};
    for (const [m, v] of Object.entries(previous?.months || {})) if (m !== month) months[m] = v;
    if (!months[prevMonth]) months[prevMonth] = await summarizeMonth(prevMonth).catch(() => undefined);
    if (!months[prevMonth]) delete months[prevMonth];
    months[month] = current;
    const order = Object.keys(months).sort((a, b) => Date.parse(`${b.slice(5)} 1, ${b.slice(0, 4)}`) - Date.parse(`${a.slice(5)} 1, ${a.slice(0, 4)}`)).slice(0, 3);
    return ok(`${month}: ${current.windowsTotal} Windows CVEs, ${current.critical} Critical, ${current.endpoint.length} Defender or Intune · ${order.length} months kept`, {
      ...current,
      months: Object.fromEntries(order.map((m) => [m, months[m]])),
      url: "https://msrc.microsoft.com/update-guide",
    });
  } catch (error) {
    return fail(error);
  }
}

async function summarizeMonth(month) {
  {
    const osRows = {};
    await Promise.all(
      Object.entries(OS_PRODUCTS).map(async ([os, names]) => {
        const filter = `releaseNumber eq '${month}' and (${names.map((n) => `product eq '${n}'`).join(" or ")})`;
        osRows[os] = await sugAll("affectedProduct", filter);
      }),
    );
    const endpointRows = await sugAll("vulnerability", `releaseNumber eq '${month}' and (contains(cveTitle,'Defender') or contains(cveTitle,'Intune') or contains(cveTitle,'Malware Protection'))`, 2);
    const endpointSeverity = {};
    await Promise.all(
      endpointRows.slice(0, 15).map(async (r) => {
        const prod = await sugAll("affectedProduct", `cveNumber eq '${r.cveNumber}'`, 1).catch(() => []);
        endpointSeverity[r.cveNumber] = prod.find((p) => p.severity)?.severity || "";
      }),
    );
    const summary = P.summarizeMsrc({ month, osRows, endpointRows, endpointSeverity });
    if (!summary.windowsTotal) throw new Error(`No Windows CVEs returned for ${month}`);
    return summary;
  }
}

export async function loadKev() {
  try {
    const json = await getJson(URLS.kev, { timeoutMs: 30000 });
    const rows = P.filterKev(json);
    // Every Microsoft CVE in the catalog, so hand-kept incidents can say whether CISA lists them.
    const microsoftCves = (json.vulnerabilities || []).filter((v) => /microsoft/i.test(v.vendorProject)).map((v) => v.cveID);
    return ok(`${rows.length} Microsoft Windows or endpoint entries in 12 months`, { rows: rows.slice(0, 60), microsoftCves, url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" });
  } catch (error) {
    return fail(error);
  }
}

const RELEASE_HEALTH = [
  { label: "Windows 11 25H2", os: ["win11"], url: "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-25h2" },
  { label: "Windows 11 24H2", os: ["win11"], url: "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2" },
  { label: "Windows Server 2025", os: ["srv2025"], url: "https://learn.microsoft.com/en-us/windows/release-health/status-windows-server-2025" },
  { label: "Windows Server 2022", os: ["srv2022"], url: "https://learn.microsoft.com/en-us/windows/release-health/status-windows-server-2022" },
  {
    label: "Windows Server 2019",
    os: ["srv2019"],
    url: "https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-1809-and-windows-server-2019",
  },
];

export async function loadKnownIssues() {
  const pages = await Promise.all(
    RELEASE_HEALTH.map(async (p) => {
      try {
        return { ...p, ok: true, rows: P.parseReleaseHealth(await getText(p.url), p.url, p.os, p.label) };
      } catch (error) {
        return { ...p, ok: false, rows: [], error: errorText(error) };
      }
    }),
  );
  if (!pages.some((p) => p.ok)) return { ok: false, detail: pages.map((p) => `${p.label}: ${p.error}`).join("; "), data: null };
  const merged = new Map();
  for (const page of pages) {
    for (const row of page.rows) {
      const key = row.title.toLowerCase();
      const seen = merged.get(key);
      if (!seen) merged.set(key, { ...row, sources: [row.source] });
      else {
        for (const os of row.os) if (!seen.os.includes(os)) seen.os.push(os);
        if (!seen.sources.includes(row.source)) seen.sources.push(row.source);
        if (/resolved/i.test(seen.status) && !/resolved/i.test(row.status)) Object.assign(seen, { status: row.status, url: row.url });
      }
    }
  }
  const isOpen = (r) => !/resolved/i.test(r.status);
  const rows = [...merged.values()]
    .filter((r) => isOpen(r) || (r.updated && Date.now() - Date.parse(r.updated) < 45 * 86400000))
    .sort((a, b) => Number(isOpen(b)) - Number(isOpen(a)) || (b.updated || "").localeCompare(a.updated || ""))
    .slice(0, 60);
  const failed = pages.filter((p) => !p.ok).map((p) => p.label);
  return ok(`${rows.filter(isOpen).length} open across ${pages.length - failed.length} pages${failed.length ? ` (failed: ${failed.join(", ")})` : ""}`, {
    rows,
    pages: pages.map(({ label, url, ok: pageOk }) => ({ label, url, ok: pageOk })),
  });
}

export async function loadIntune() {
  try {
    const [whatsNew, inDev] = await Promise.all([
      getText(URLS.intuneWhatsNew).then((h) => P.parseIntuneWhatsNew(h, URLS.intuneWhatsNew)),
      getText(URLS.intuneInDev)
        .then((h) => P.parseIntuneInDevelopment(h, URLS.intuneInDev))
        .catch(() => null),
    ]);
    if (!whatsNew.length) throw new Error("No weekly headings found");
    const filled = whatsNew.filter((w) => w.items.length);
    return ok(`${filled.length} weeks with ${filled.reduce((n, w) => n + w.items.length, 0)} Windows or security items · ${inDev ? inDev.length : "no"} in-development items`, {
      weeks: whatsNew,
      inDevelopment: inDev || [],
      inDevelopmentOk: Boolean(inDev),
      url: URLS.intuneWhatsNew,
      inDevelopmentUrl: URLS.intuneInDev,
    });
  } catch (error) {
    return fail(error);
  }
}

export async function loadMdeWhatsNew() {
  try {
    // A feature listed twice (preview, then GA) is shown once with both stages.
    const items = [];
    for (const item of P.parseMdeWhatsNew(await getText(URLS.mdeWhatsNew), URLS.mdeWhatsNew)) {
      const same = items.find((i) => i.name.toLowerCase() === item.name.toLowerCase());
      if (!same) items.push({ ...item, history: [] });
      else same.history.push({ stage: item.stage, when: item.when });
    }
    if (!items.length) throw new Error("No monthly items found");
    return ok(`${items.length} Windows items`, { items, url: URLS.mdeWhatsNew });
  } catch (error) {
    return fail(error);
  }
}

const FEEDS = [
  { source: "Microsoft Security Blog", url: "https://www.microsoft.com/en-us/security/blog/feed/" },
  { source: "MSRC Security Update Guide", url: "https://api.msrc.microsoft.com/update-guide/rss", limit: 80 },
  { source: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { source: "SecurityWeek", url: "https://www.securityweek.com/feed/" },
  { source: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
];

/** RSS fetch with plain headers first: BleepingComputer's Cloudflare answers 403 to the full browser header set from cloud runners, and 200 to this. */
async function feedText(url) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const res = await fetch(url, { headers: { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", accept: "application/rss+xml,*/*" }, signal: AbortSignal.timeout(25000) });
      if (res.ok) return await res.text();
      if (attempt) throw new Error(`HTTP ${res.status}`);
    } catch (error) {
      if (attempt) throw error;
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  return getText(url, { timeoutMs: 25000 });
}

export async function loadNews() {
  const packs = await Promise.all(
    FEEDS.map(async (f) => {
      try {
        // RSS accept header: some feeds behind Cloudflare refuse a browser-style HTML accept from cloud runners.
        const text = await feedText(f.url);
        const items = P.parseFeed(text, f.source, f.limit || 30);
        if (!items.length) throw new Error("Feed returned no items");
        return { source: f.source, ok: true, items };
      } catch (error) {
        return { source: f.source, ok: false, items: [], error: errorText(error) };
      }
    }),
  );
  if (!packs.some((p) => p.ok)) return { ok: false, detail: "Every feed failed", data: null };
  const seen = new Set();
  const items = [];
  for (const item of packs.flatMap((p) => p.items)) {
    if (!P.isEndpointNews(item)) continue;
    const key = item.url.replace(/[?#].*$/, "").replace(/\/$/, "");
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({ ...item, id: key, os: osTags(`${item.title} ${item.summary}`) });
  }
  items.sort((a, b) => (b.published || "").localeCompare(a.published || ""));
  const failed = packs.filter((p) => !p.ok).map((p) => p.source);
  return ok(`${items.length} relevant headlines from ${packs.length - failed.length} feeds${failed.length ? ` (failed: ${packs.filter((p) => !p.ok).map((p) => `${p.source}: ${p.error}`).join(", ")})` : ""}`, {
    items: items.slice(0, 40),
    feeds: packs.map(({ source, ok: feedOk, error }) => ({ source, ok: feedOk, error: error || "" })),
  });
}

export async function loadSense() {
  try {
    const rows = P.parseSenseCatalog(await getText(URLS.senseCatalog, { timeoutMs: 30000 }));
    if (!rows.length) throw new Error("No Sense build found in the Update Catalog");
    // The catalog lists one row per OS family, each with its own "last updated" date (no time).
    const builds = rows
      .filter((r) => r.version === rows[0].version)
      .map((r) => ({ date: r.date, channel: r.channel, os: /Windows Server 2019\+/i.test(r.title) ? "Windows Server 2019 and later" : /Windows 10\/11/i.test(r.title) ? "Windows 10 and 11" : /Windows 7/i.test(r.title) ? "Windows 7 / Server 2008 R2" : "Other" }));
    return ok(`Latest ${rows[0].version} · ${rows[0].channel || "channel not stated"}`, { latest: { ...rows[0], title: rows[0].title.replace(/^[^>]*>\s*/, "") }, builds, url: URLS.senseCatalog });
  } catch (error) {
    return fail(error);
  }
}

/** Qualys QIDs for this month and the month before, merged with months already stored. */
export async function loadQualys(month, previous) {
  const months = { ...(previous?.months || {}) };
  if (previous?.month && previous?.qids && !months[previous.month]) months[previous.month] = { url: previous.url, qids: previous.qids, query: previous.query };
  const prevMonth = (() => {
    const d = new Date(`${month.slice(5)} 1, ${month.slice(0, 4)} UTC`);
    if (Number.isNaN(d.getTime())) return "";
    d.setUTCMonth(d.getUTCMonth() - 1);
    return `${d.getUTCFullYear()}-${d.toLocaleString("en-US", { month: "short", timeZone: "UTC" })}`;
  })();
  const errors = [];
  for (const m of [month, prevMonth].filter(Boolean)) {
    if (m !== month && months[m]) continue;
    const r = await loadQualysMonth(m);
    if (r.ok) months[m] = r.data;
    else errors.push(`${m}: ${r.detail}`);
  }
  const order = Object.keys(months).sort((a, b) => Date.parse(`${b.slice(5)} 1, ${b.slice(0, 4)}`) - Date.parse(`${a.slice(5)} 1, ${a.slice(0, 4)}`)).slice(0, 6);
  if (!order.length) return { ok: false, detail: errors.join("; ") || "No Qualys review found", data: null };
  const kept = Object.fromEntries(order.map((m) => [m, months[m]]));
  const latest = kept[month] ? month : order[0];
  return ok(`${order.map((m) => `${kept[m].qids.length} QIDs for ${m}`).join(", ")}${errors.length ? ` (not yet: ${errors.join("; ")})` : ""}`, { month: latest, months: kept, ...kept[latest] });
}

async function loadQualysMonth(month) {
  try {
    const links = {};
    for (let page = 1; page <= 4; page += 1) {
      const html = await getText(page === 1 ? "https://threatprotect.qualys.com/" : `https://threatprotect.qualys.com/page/${page}/`, { timeoutMs: 15000, retries: 1 }).catch(() => "");
      Object.assign(links, P.parseQualysIndex(html), links);
      if (links[month]) break;
    }
    const url = links[month];
    if (!url) throw new Error(`No Qualys Patch Tuesday review for ${month} yet`);
    const qids = P.parseQualysQids(await getText(url, { timeoutMs: 20000 }));
    if (!qids.length) throw new Error("Review found but no QIDs listed");
    return ok(`${qids.length} QIDs for ${month}`, { url, qids, query: `vulnerabilities.vulnerability.qid:[${qids.join(", ")}]` });
  } catch (error) {
    return fail(error);
  }
}

export async function loadPublicHashes(previous) {
  try {
    const rows = await getJson("https://api.tweetfeed.live/v1/week/sha256", { timeoutMs: 30000 });
    const picked = [];
    const seen = new Set();
    const newest = (Array.isArray(rows) ? rows : []).slice().sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")));
    for (const r of newest) {
      const hash = String(r.value || "").toLowerCase();
      if (!/^[a-f0-9]{64}$/.test(hash) || seen.has(hash)) continue;
      seen.add(hash);
      picked.push({ hash, reportedAt: r.date ? toIso(`${String(r.date).replace(" ", "T")}Z`) : "", reporter: r.user || "", tags: (r.tags || []).join(" "), tweet: r.tweet || "" });
      if (picked.length >= 30) break;
    }
    // Re-check earlier hashes that had no analysis yet, then add today's new ones. Keep the latest 20.
    const earlier = (previous?.rows || []).filter((r) => !seen.has(r.hash));
    const queue = [...picked, ...earlier.filter((r) => !r.analysed).slice(0, 6)];
    const out = [];
    for (const item of queue) {
      const res = await getJson(`https://otx.alienvault.com/api/v1/indicators/file/${item.hash}/analysis`, { timeoutMs: 15000, retries: 0 }).catch(() => null);
      const a = res ? P.parseOtxAnalysis(item.hash, res) : { hash: item.hash, analysed: false, fileType: "", defender: "", other: "" };
      if (a.fileType && !/pe32|pe64|windows|win32|dll|executable|ms-dos/i.test(a.fileType)) continue;
      out.push({ ...item, ...a, checkedAt: new Date().toISOString(), vt: `https://www.virustotal.com/gui/file/${item.hash}`, otx: `https://otx.alienvault.com/indicator/file/${item.hash}` });
    }
    const done = new Set(out.map((r) => r.hash));
    out.push(...earlier.filter((r) => !done.has(r.hash)));
    out.sort((a, b) => (b.reportedAt || "").localeCompare(a.reportedAt || ""));
    out.splice(20);
    const gaps = out.filter((r) => r.other && !r.defender).length;
    return ok(`${out.length} Windows hashes kept, ${out.filter((r) => r.analysed).length} analysed, ${gaps} where another scanner names it and Defender does not`, { rows: out });
  } catch (error) {
    return fail(error);
  }
}

export async function loadRoadmap() {
  try {
    const res = await getText("https://www.microsoft.com/releasecommunications/api/v1/m365", { timeoutMs: 25000, accept: "application/json" });
    const t = res.trim();
    if (!t.startsWith("{") && !t.startsWith("[")) throw new Error("The roadmap API did not return JSON on this run");
    const seen = new Set();
    const rows = P.filterRoadmap(JSON.parse(t))
      .sort((a, b) => (b.updated || "").localeCompare(a.updated || ""))
      .filter((r) => {
        const key = r.title.toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .map((r) => ({ ...r, core: /^Microsoft (Intune|Defender for Endpoint)\b/i.test(r.title) }))
      .slice(0, 40);
    return ok(`${rows.length} items stored, ${rows.filter((r) => r.core).length} for Defender for Endpoint or Intune`, { rows, url: "https://www.microsoft.com/microsoft-365/roadmap?filters=Microsoft%20Defender%20for%20Endpoint,Microsoft%20Intune" });
  } catch (error) {
    return fail(error);
  }
}
