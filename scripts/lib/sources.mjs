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
  return ok(`${good.length} of ${results.length} packages resolved${wimPage ? "" : " (offline image page not read)"}`, results);
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
      const json = await getJson(`https://arctic-shift.photon-reddit.com/api/posts/search?${q}`, { timeoutMs: 15000 });
      packs.push({ sub, ok: true, posts: P.parseRedditPosts(json, sub, filter) });
    } catch (error) {
      packs.push({ sub, ok: false, posts: [], error: errorText(error) });
    }
    await new Promise((r) => setTimeout(r, 900));
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
    // The changelog clock is the same as the definitions clock; the collector converts it.
    return ok(`${parsed.version} · ${parsed.rows.length} detections`, { ...parsed, rows: parsed.rows.slice(0, 120), url: URLS.changelog });
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

export async function loadPatchTuesday(now = new Date()) {
  try {
    // Before this month's Patch Tuesday, the latest Windows release is last month's.
    const thisPt = secondTuesday(now.getUTCFullYear(), now.getUTCMonth());
    const ref = now.getTime() >= thisPt.getTime() + 17 * 3600000 ? now : new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
    const month = releaseNumber(ref);
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
    return ok(`${month}: ${summary.windowsTotal} Windows CVEs, ${summary.critical} Critical, ${summary.endpoint.length} Defender or Intune`, {
      ...summary,
      url: "https://msrc.microsoft.com/update-guide",
    });
  } catch (error) {
    return fail(error);
  }
}

export async function loadKev() {
  try {
    const rows = P.filterKev(await getJson(URLS.kev, { timeoutMs: 30000 }));
    return ok(`${rows.length} Microsoft Windows or endpoint entries in 12 months`, { rows: rows.slice(0, 60), url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" });
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
    return ok(`${whatsNew.length} weeks, ${whatsNew.reduce((n, w) => n + w.items.length, 0)} Windows or security items`, {
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
    const items = P.parseMdeWhatsNew(await getText(URLS.mdeWhatsNew), URLS.mdeWhatsNew);
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

export async function loadNews() {
  const packs = await Promise.all(
    FEEDS.map(async (f) => {
      try {
        return { source: f.source, ok: true, items: P.parseFeed(await getText(f.url), f.source, f.limit || 30) };
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
  return ok(`${items.length} relevant headlines from ${packs.length - failed.length} feeds${failed.length ? ` (failed: ${failed.join(", ")})` : ""}`, {
    items: items.slice(0, 40),
    feeds: packs.map(({ source, ok: feedOk, error }) => ({ source, ok: feedOk, error: error || "" })),
  });
}

export async function loadSense() {
  try {
    const rows = P.parseSenseCatalog(await getText(URLS.senseCatalog, { timeoutMs: 30000 }));
    if (!rows.length) throw new Error("No Sense build found in the Update Catalog");
    return ok(`Latest ${rows[0].version}`, { latest: rows[0], url: URLS.senseCatalog });
  } catch (error) {
    return fail(error);
  }
}
