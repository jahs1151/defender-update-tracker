// Detection-name lookup over the 30-day detection index (data/detections.json), shared by the browser
// page and the Node tests. Pure functions: no DOM, no network.
//
// The index is { versions: { "1.463.510.0": { releasedAt, names: [...] } } }. A build's changelog page lists
// the detections that build added or updated, so the first build a name appears in is when Microsoft first
// listed it inside the window. For the newest builds the per-build files say "added" or "updated".

/** Letters and digits only, lower case: "Trojan:Win32/Wacatac.B!ml" -> "trojanwin32wacatacbml". */
export const compactName = (s = "") => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "");

const cmpVersion = (a, b) => {
  const x = String(a).split(".").map(Number);
  const y = String(b).split(".").map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0);
  return 0;
};

/** Oldest first: by release time, then by version number. */
const byRelease = (a, b) => (a.releasedAt || "").localeCompare(b.releasedAt || "") || cmpVersion(a.version, b.version);

/** The builds in the index and how far back they go. */
export function indexWindow(versions = {}) {
  const list = Object.entries(versions).map(([version, e]) => ({ version, releasedAt: e?.releasedAt || "" })).sort(byRelease);
  const dated = list.filter((b) => b.releasedAt);
  return { builds: list.length, from: dated[0]?.releasedAt || "", to: dated[dated.length - 1]?.releasedAt || "", oldest: list[0]?.version || "", newest: list[list.length - 1]?.version || "" };
}

/**
 * Names containing the query, ignoring case, spaces, "!" and other punctuation, so "LinPeas",
 * "wacatac b ml", "Wacatac.B!ml" and "Trojan:Win32/Wacatac" all find what they should.
 * Returns { query, tooShort, total, matches: [{ name, first, last, count, builds }] }, best match first.
 * builds: every build that lists the name, oldest first, [{ version, releasedAt }].
 */
export function findDetections(versions = {}, query = "", { limit = 40, minLength = 3 } = {}) {
  const q = compactName(query);
  if (q.length < minLength) return { query: String(query).trim(), tooShort: true, total: 0, matches: [] };
  const byName = new Map();
  for (const [version, e] of Object.entries(versions)) {
    for (const name of e?.names || []) {
      const c = compactName(name);
      if (!c.includes(q)) continue;
      if (!byName.has(name)) byName.set(name, { name, compact: c, builds: [] });
      byName.get(name).builds.push({ version, releasedAt: e.releasedAt || "" });
    }
  }
  const family = (c, n) => compactName(n.replace(/^[^/]*\//, ""));
  const rank = (m) => (m.compact === q ? 0 : family(m.compact, m.name).startsWith(q) ? 1 : 2);
  const all = [...byName.values()].map((m) => {
    const builds = m.builds.sort(byRelease);
    return { name: m.name, first: builds[0], last: builds[builds.length - 1], count: builds.length, builds, rank: rank(m) };
  });
  // Best match first, then the most recently first-listed.
  all.sort((a, b) => a.rank - b.rank || byRelease(b.first, a.first) || a.name.localeCompare(b.name));
  return { query: String(query).trim(), tooShort: false, total: all.length, matches: all.slice(0, limit).map(({ rank: _r, ...m }) => m) };
}

/**
 * How to describe the first listing of a name. changes: { [version]: "added" | "updated" } from the
 * per-build files (only the newest builds have one).
 *   added:   the build's own page says the name was added there.
 *   updated: it was listed as an update, so the name was added before this build.
 *   listed:  no per-build detail for that build; the page lists additions and updates alike.
 */
export function firstListing(match, changes = {}) {
  const kind = changes[match.first.version] || "listed";
  const label = { added: "Added in", updated: "First listed, as an update, in", listed: "First listed in" }[kind];
  const note = {
    added: "",
    updated: "It was added before this build, and the build that added it is older than the data kept here or was not listed.",
    listed: "The changelog lists a build's additions and updates together, and older builds do not say which this was.",
  }[kind];
  return { kind, label, note };
}

/** The sentence shown when nothing matches, including how far back the data goes. */
export function notFoundText(query, win) {
  const range = win.from ? `${win.builds} builds from ${win.oldest} (${win.from.slice(0, 10)}) to ${win.newest} (${win.to.slice(0, 10)})` : `${win.builds} builds`;
  const other = /\b(linux|macos|osx|android|ios|iphone|unix)\b/i.test(query) ? " Names for Linux, macOS, Android and iOS are not tracked: this site is Windows only." : " Names for Linux, macOS, Android and iOS are not tracked here.";
  return `No Windows detection matching "${String(query).trim()}" in the last 30 days of Microsoft's changelog (${range}).${other} A name added earlier than that is not in this data. Try a shorter part, such as just the family name.`;
}

/**
 * Handlers for the lookup form, written so a phone keyboard's Enter, Go or Search key works.
 * Pass them to document.addEventListener. run(query) does the search; submit and keydown both call it,
 * keydown only for Enter and with preventDefault so the form does not also submit.
 */
export function detectionHandlers(run, { delay = 250, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  let timer = null;
  return {
    onSubmit(e) {
      if (e.target?.id !== "det-form") return false;
      e.preventDefault();
      clearTimer(timer);
      const input = e.target.querySelector?.("#det-q");
      run(input ? input.value : "");
      input?.blur?.();
      return true;
    },
    onKeydown(e) {
      if (e.target?.id !== "det-q" || (e.key !== "Enter" && e.keyCode !== 13)) return false;
      e.preventDefault();
      clearTimer(timer);
      run(e.target.value);
      e.target.blur?.();
      return true;
    },
    onInput(e) {
      if (e.target?.id !== "det-q") return false;
      clearTimer(timer);
      const value = e.target.value;
      timer = setTimer(() => run(value), delay);
      return true;
    },
  };
}
