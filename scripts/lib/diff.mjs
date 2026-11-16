// "What changed" between two pulse snapshots, and a key that ignores timestamps.

const pick = (pulse) => {
  const s = pulse?.sections || {};
  const d = (k) => s[k]?.data || {};
  const packages = Array.isArray(s.packages?.data) ? s.packages.data : [];
  const latestProduct = d("productUpdates").rows?.[0] || {};
  return {
    "Security intelligence": d("intelligence").securityIntelligence || "",
    Engine: d("intelligence").engine || "",
    Platform: d("intelligence").platform || "",
    "mpam-fe.exe": packages.find((p) => p.id === "mpam-fe")?.version || "",
    "updateplatform.exe": packages.find((p) => p.id === "updateplatform")?.version || "",
    "Offline image kit": packages.find((p) => p.id === "wim")?.version || "",
    "Monthly platform release": latestProduct.platform || "",
    "Monthly engine release": latestProduct.engine || "",
    "Sense build": d("sense").latest?.version || "",
    "Patch Tuesday month": d("patchTuesday").month || "",
    "Patch Tuesday Windows CVEs": String(d("patchTuesday").windowsTotal ?? ""),
    "Defender or Intune CVEs": (d("patchTuesday").endpoint || []).map((r) => r.cve).join(", "),
    "Newest KEV entry": d("kev").rows?.[0]?.cve || "",
    "Open known issues": (d("knownIssues").rows || []).filter((r) => !/resolved/i.test(r.status)).map((r) => r.title),
    "Latest headline": d("news").items?.[0]?.title || "",
    "Latest Intune week": d("intune").weeks?.[0]?.week || "",
  };
};

export function contentKey(pulse) {
  return JSON.stringify(pick(pulse));
}

export function diffPulse(before, after) {
  const a = pick(before);
  const b = pick(after);
  const out = [];
  for (const key of Object.keys(b)) {
    if (Array.isArray(b[key])) {
      const added = b[key].filter((x) => !(a[key] || []).includes(x));
      const removed = (a[key] || []).filter((x) => !b[key].includes(x));
      for (const t of added) out.push({ field: key, kind: "added", to: t });
      for (const t of removed) out.push({ field: key, kind: "removed", from: t });
    } else if (a[key] !== b[key] && b[key]) {
      out.push({ field: key, kind: a[key] ? "changed" : "added", from: a[key] || "", to: b[key] });
    }
  }
  return out.slice(0, 30);
}
