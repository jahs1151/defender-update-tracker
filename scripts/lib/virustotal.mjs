// VirusTotal file lookups for the public hash list. The API key comes from the VIRUSTOTAL_API_KEY
// environment variable (a GitHub Actions secret). It is sent only in the x-apikey header and is never
// logged, stored or written to pulse.json. Public API limits: 4 lookups a minute, 500 a day.

export const VT_LIMITS = { perMinute: 4, perDay: 500, cacheHours: 24 };

/** One /api/v3/files/{hash} answer -> what the page needs. */
export function parseVtFile(json) {
  const a = json?.data?.attributes || {};
  const results = a.last_analysis_results || {};
  const engines = Object.entries(results);
  const bad = (r) => r && (r.category === "malicious" || r.category === "suspicious");
  const ms = results.Microsoft || null;
  const others = engines.filter(([k, r]) => k !== "Microsoft" && bad(r));
  const microsoft = bad(ms) ? ms.result || "Detected" : "";
  return {
    found: true,
    malicious: Number(a.last_analysis_stats?.malicious || 0),
    total: engines.length,
    others: others.length,
    microsoft,
    microsoftState: !ms ? "not scanned" : microsoft ? "detected" : ms.category || "undetected",
    // Other engines detect it and Microsoft does not (Microsoft scanned it, or was not in the scan).
    gap: others.length > 0 && !microsoft,
    analysedAt: a.last_analysis_date ? new Date(a.last_analysis_date * 1000).toISOString() : "",
    fileType: a.type_description || "",
  };
}

/**
 * Look up hashes not checked in the last 24 hours, within the minute and day limits.
 * rows: [{ hash, vtResult? }]; budget: { day, used } from the last run.
 * Returns { rows, budget, status: "ok" | "no-key" | "rejected" | "limited", checked }.
 */
export async function vtLookup(rows, { key, budget = {}, now = new Date(), maxPerRun = 8, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  if (!key) return { rows, budget, status: "no-key", checked: 0 };
  const day = now.toISOString().slice(0, 10);
  const b = { day, used: budget.day === day ? Number(budget.used || 0) : 0 };
  const fresh = new Date(now.getTime() - VT_LIMITS.cacheHours * 3600000).toISOString();
  const due = rows.filter((r) => !r.vtResult?.checkedAt || r.vtResult.checkedAt < fresh || r.vtResult.error);
  const out = new Map(rows.map((r) => [r.hash, r]));
  let status = "ok";
  let checked = 0;
  for (const r of due.slice(0, maxPerRun)) {
    if (b.used >= VT_LIMITS.perDay) {
      status = "limited";
      break;
    }
    if (checked) await sleep(Math.ceil(60000 / VT_LIMITS.perMinute));
    b.used += 1;
    checked += 1;
    let res;
    try {
      res = await fetchImpl(`https://www.virustotal.com/api/v3/files/${r.hash}`, { headers: { "x-apikey": key, accept: "application/json" }, signal: AbortSignal.timeout(20000) });
    } catch (e) {
      out.set(r.hash, { ...r, vtResult: { error: e?.name === "TimeoutError" ? "timed out" : "network error", checkedAt: now.toISOString() } });
      continue;
    }
    if (res.status === 401 || res.status === 403) {
      status = "rejected";
      break;
    }
    if (res.status === 429) {
      status = "limited";
      break;
    }
    const checkedAt = new Date().toISOString();
    if (res.status === 404) out.set(r.hash, { ...r, vtResult: { found: false, checkedAt } });
    else if (res.ok) out.set(r.hash, { ...r, vtResult: { ...parseVtFile(await res.json()), checkedAt } });
    else out.set(r.hash, { ...r, vtResult: { error: `HTTP ${res.status}`, checkedAt } });
  }
  return { rows: rows.map((r) => out.get(r.hash)), budget: b, status, checked };
}
