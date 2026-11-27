// "What changed" between two pulse snapshots, and a key that ignores timestamps.

const pick = (pulse) => {
  const s = pulse?.sections || {};
  const d = (k) => s[k]?.data || {};
  const packages = Array.isArray(s.packages?.data) ? s.packages.data : [];
  const sense = d("sense");
  const threats = s.threats?.data;
  // Fields added in schema 4 are undefined in an older snapshot, and diffPulse skips them, so
  // the first run after an upgrade does not report every Sense release and alert as new.
  const issues = {};
  for (const i of sense.issues || []) issues[`Sense issue: ${i.title}`] = i.stage || "Tracked";
  return {
    "Security intelligence": d("intelligence").securityIntelligence || "",
    Engine: d("intelligence").engine || "",
    Platform: d("intelligence").platform || "",
    "mpam-fe.exe": packages.find((p) => p.id === "mpam-fe")?.version || "",
    "updateplatform.exe": packages.find((p) => p.id === "updateplatform")?.version || "",
    "Offline image kit": packages.find((p) => p.id === "wim")?.version || "",
    "Sense build": d("sense").latest?.version || "",
    "Patch Tuesday month": d("patchTuesday").month || "",
    "Patch Tuesday Windows CVEs": String(d("patchTuesday").windowsTotal ?? ""),
    "Defender or Intune CVEs": (d("patchTuesday").endpoint || []).map((r) => r.cve).join(", "),
    "Newest KEV entry": d("kev").rows?.[0]?.cve || "",
    "Open known issues": (d("knownIssues").rows || []).filter((r) => !/resolved/i.test(r.status)).map((r) => r.title),
    "Latest headline": d("news").items?.[0]?.title || "",
    "Latest Intune week": d("intune").weeks?.[0]?.week || "",
    "Sense releases": sense.releases ? sense.releases.map((r) => r.version) : undefined,
    "KB5005292 known issues": sense.kb?.ok ? sense.kb.knownIssues || "None listed" : undefined,
    ...issues,
    "Detection alerts": threats?.alerts ? threats.alerts.map((a) => `${a.detection} in ${a.version} (named in ${a.story.source}: ${a.threat})`) : undefined,
    // The encyclopedia answered with no entry and the 30-day changelog has none.
    "Threats with no Defender detection found": threats?.coverage && threats?.kev ? [...new Set([...threats.coverage.filter((r) => r.coverage === "Unclear").map((r) => `${r.threat} (${r.vendor})`), ...threats.kev.filter((r) => !r.detections.length).map((r) => `${r.cve} (CISA KEV, due ${r.dueDate})`)])] : undefined,
  };
};

/** Lists where only new entries are news: an alert or vendor post ageing out is not a change worth sending. */
const ADD_ONLY = new Set(["Sense releases", "Detection alerts", "Threats with no Defender detection found"]);

export function contentKey(pulse) {
  return JSON.stringify(pick(pulse));
}

export function diffPulse(before, after) {
  const a = pick(before);
  const b = pick(after);
  const out = [];
  for (const key of Object.keys(b)) {
    if (b[key] === undefined || a[key] === undefined) continue;
    if (Array.isArray(b[key])) {
      const added = b[key].filter((x) => !(a[key] || []).includes(x));
      const removed = (a[key] || []).filter((x) => !b[key].includes(x));
      for (const t of added) out.push({ field: key, kind: "added", to: t });
      if (!ADD_ONLY.has(key)) for (const t of removed) out.push({ field: key, kind: "removed", from: t });
    } else if (a[key] !== b[key] && b[key]) {
      out.push({ field: key, kind: a[key] ? "changed" : "added", from: a[key] || "", to: b[key] });
    }
  }
  return out.slice(0, 30);
}
