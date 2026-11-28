// VirusTotal file lookups for the public hash list. The API key comes from the VIRUSTOTAL_API_KEY
// environment variable (a GitHub Actions secret). It is sent only in the x-apikey header and is never
// logged, stored or written to pulse.json. Public API limits: 4 lookups a minute, 500 a day.

export const VT_LIMITS = { perMinute: 4, perDay: 500, cacheHours: 24 };

import { NON_WINDOWS_WORDS, fileTypePlatform } from "./platform.mjs";

const NON_WIN = NON_WINDOWS_WORDS;
const WIN = /\b(?:win(?:32|64|dows)?|msil|lnk|pe32|pe64|peexe|dll|vbs|vba|o97m|powershell|ps1|bat|cmd|js|jscript|hta|html|msi|w97m|x97m)\b/i;

/**
 * Which platform a VirusTotal file targets: "windows", "other" or "unknown". A ZIP or RAR is judged by
 * what is inside (type tags such as "android" or "apk", and the names engines give it), so a ZIP holding
 * a Windows shortcut stays Windows while a ZIP holding an Android dropper does not.
 */
export function vtPlatform(attrs = {}) {
  // The file type VirusTotal reports comes first: Android, ELF, Mach-O, iOS and shell scripts are out,
  // PE files, MSI, LNK, Office documents and Windows scripts are in. Archives fall through to the checks below.
  const byType = fileTypePlatform([attrs.type_description, attrs.type_tag].filter(Boolean).join(" "));
  if (byType === "other") return "other";
  if (byType === "windows") return "windows";
  const tags = [attrs.type_tag, ...(attrs.tags || []), attrs.type_description].filter(Boolean).join(" ").replace(/[-_]/g, " ");
  if (/\b(?:peexe|pedll|lnk|windows|win32|win64|msi)\b/i.test(tags)) return "windows";
  if (/\b(?:android|apk|dex|elf|linux|macho|mach o|macos|ios|ipa|shell|bash)\b/i.test(tags)) return "other";
  const names = Object.values(attrs.last_analysis_results || {}).map((r) => r?.result || "").filter(Boolean).map((n) => n.replace(/[\/:._!-]/g, " "));
  const other = names.filter((n) => NON_WIN.test(n) && !WIN.test(n)).length;
  const win = names.filter((n) => WIN.test(n)).length;
  if (other >= 2 && other > win) return "other";
  if (win > 0) return "windows";
  return "unknown";
}

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
    platform: vtPlatform(a),
  };
}

/**
 * Look up hashes not checked in the last 24 hours, within the minute and day limits.
 * rows: [{ hash, vtResult? }]; budget: { day, used } from the last run.
 * Returns { rows, budget, status: "ok" | "no-key" | "rejected" | "limited", checked }.
 */
/** A pasted secret often carries spaces, a newline or quotes. VirusTotal keys are 64 hex characters. */
export function cleanKey(raw = "") {
  return String(raw).trim().replace(/^["']|["']$/g, "").trim();
}

/** What is wrong with a key's shape, without revealing any of it. "" when it looks right. */
export function keyShape(key = "") {
  return /^[a-f0-9]{64}$/i.test(key) ? "" : `the secret is ${key.length} characters and VirusTotal keys are 64 letters and digits (0-9, a-f)`;
}

export async function vtLookup(rows, { key, budget = {}, now = new Date(), maxPerRun = 8, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  if (!key) return { rows, budget, status: "no-key", checked: 0 };
  const day = now.toISOString().slice(0, 10);
  const b = { day, used: budget.day === day ? Number(budget.used || 0) : 0 };
  const fresh = new Date(now.getTime() - VT_LIMITS.cacheHours * 3600000).toISOString();
  // Answers saved before the platform check (no "platform" field) are asked again once.
  const due = rows.filter((r) => !r.vtResult?.checkedAt || r.vtResult.checkedAt < fresh || r.vtResult.error || (r.vtResult.found && !r.vtResult.platform));
  const out = new Map(rows.map((r) => [r.hash, r]));
  let status = "ok";
  let reason = "";
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
      // VirusTotal names the reason (WrongCredentialsError, ForbiddenError ...). It never echoes the key.
      const body = typeof res.json === "function" ? await res.json().catch(() => null) : null;
      reason = `HTTP ${res.status}${body?.error?.code ? ` ${String(body.error.code).replace(/[^A-Za-z]/g, "").slice(0, 40)}` : ""}`;
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
  return { rows: rows.map((r) => out.get(r.hash)), budget: b, status, checked, reason };
}
