// Time helpers shared by the browser page and the Node collector.
// Every release time is shown in UTC first, then America/Chicago with the
// correct CST/CDT label, for example "15 Nov 2026, 23:50 UTC · 15 Nov 2026, 17:50 CST".

const CHICAGO = "America/Chicago";

const dayFmt = (timeZone) =>
  new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone });
const timeFmt = (timeZone) =>
  new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone });
const zoneNameFmt = new Intl.DateTimeFormat("en-US", { timeZone: CHICAGO, timeZoneName: "short" });

function toDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value !== "string" || !value.trim()) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** "CST" or "CDT" for the given instant. */
export function chicagoZone(date) {
  const part = zoneNameFmt.formatToParts(date).find((p) => p.type === "timeZoneName");
  return part ? part.value : "CT";
}

/** Has a real time of day (ISO with a "T"), as opposed to a date-only value. */
export function hasTime(value) {
  return typeof value === "string" ? /T\d{2}:\d{2}/.test(value) : value instanceof Date;
}

/**
 * Full stamp: "15 Nov 2026, 23:50 UTC · 15 Nov 2026, 17:50 CST".
 * Date-only values ("2026-11-10") are shown as a date with no zone, because
 * Microsoft did not publish a time for them.
 */
export function stamp(value, { fallback = "Time not published" } = {}) {
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const d = new Date(`${value}T12:00:00Z`);
    return `${dayFmt("UTC").format(d)} (date only)`;
  }
  const d = toDate(value);
  if (!d) return fallback;
  const utc = `${dayFmt("UTC").format(d)}, ${timeFmt("UTC").format(d)} UTC`;
  const ct = `${dayFmt(CHICAGO).format(d)}, ${timeFmt(CHICAGO).format(d)} ${chicagoZone(d)}`;
  return `${utc} · ${ct}`;
}

/** Short relative age, e.g. "12 min ago", "3 h ago", "2 days ago". */
export function ago(value, now = new Date()) {
  const d = toDate(value);
  if (!d) return "";
  const mins = Math.round((now.getTime() - d.getTime()) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

/** Offset in minutes of `timeZone` from UTC at the given instant. */
function offsetMinutes(date, timeZone) {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(date);
  const get = (t) => Number(parts.find((p) => p.type === t).value);
  const asUtc = Date.UTC(get("year"), get("month") - 1, get("day"), get("hour") % 24, get("minute"), get("second"));
  return Math.round((asUtc - date.getTime()) / 60000);
}

/** Wall-clock fields in `timeZone` to a UTC Date. */
export function zonedToUtc(fields, timeZone) {
  const { year, month, day, hour = 0, minute = 0, second = 0 } = fields;
  const guess = Date.UTC(year, month - 1, day, hour, minute, second);
  if (timeZone === "UTC") return new Date(guess);
  let utc = guess - offsetMinutes(new Date(guess), timeZone) * 60000;
  // Second pass handles the hours around a DST change.
  utc = guess - offsetMinutes(new Date(utc), timeZone) * 60000;
  return new Date(utc);
}

/**
 * Parse Microsoft's US-format clock, e.g. "11/15/2026 11:50:45 PM", which carries
 * no time zone. `timeZone` says which zone the page clock is in.
 */
export function parseUsClock(text, timeZone = "UTC") {
  const m = /(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AP]M)?/i.exec(text || "");
  if (!m) return null;
  let hour = Number(m[4]);
  const ampm = (m[7] || "").toUpperCase();
  if (ampm === "PM" && hour < 12) hour += 12;
  if (ampm === "AM" && hour === 12) hour = 0;
  return zonedToUtc(
    { year: Number(m[3]), month: Number(m[1]), day: Number(m[2]), hour, minute: Number(m[5]), second: Number(m[6] || 0) },
    timeZone,
  );
}

/** Second Tuesday of a month (UTC date). */
export function secondTuesday(year, monthIndex) {
  const first = new Date(Date.UTC(year, monthIndex, 1));
  return new Date(Date.UTC(year, monthIndex, 1 + ((2 - first.getUTCDay() + 7) % 7) + 7));
}

/** Last and next Patch Tuesday around `now`, and whether we are inside the patch window. */
export function patchWindow(now = new Date()) {
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth();
  const thisMonth = secondTuesday(y, m);
  const prev = m === 0 ? secondTuesday(y - 1, 11) : secondTuesday(y, m - 1);
  const nextMonth = m === 11 ? secondTuesday(y + 1, 0) : secondTuesday(y, m + 1);
  const onOrAfter = now.getTime() >= thisMonth.getTime();
  const last = onOrAfter ? thisMonth : prev;
  const next = onOrAfter ? nextMonth : thisMonth;
  const daysAfter = (now.getTime() - last.getTime()) / 86400000;
  return {
    last: last.toISOString().slice(0, 10),
    next: next.toISOString().slice(0, 10),
    inWindow: daysAfter <= 8,
  };
}

/** Compare dotted versions numerically. */
export function cmpVersion(a, b) {
  const l = String(a || "").split(".").map((x) => Number(x) || 0);
  const r = String(b || "").split(".").map((x) => Number(x) || 0);
  for (let i = 0; i < Math.max(l.length, r.length); i += 1) {
    const d = (l[i] || 0) - (r[i] || 0);
    if (d) return d;
  }
  return 0;
}

/** Month code from a Defender version: 4.18.26100.4 -> 2610 (October 2026 build). */
export function versionMonth(version) {
  const third = String(version || "").split(".")[2] || "";
  const code = Number(third.slice(0, 4));
  if (!code) return null;
  const yy = Math.floor(code / 100);
  const mm = code % 100;
  return mm >= 1 && mm <= 12 ? yy * 12 + (mm - 1) : null;
}

/** Months between two Defender versions by their month code (a - b), or null. */
export function monthsBetween(a, b) {
  const x = versionMonth(a);
  const y = versionMonth(b);
  return x == null || y == null ? null : x - y;
}
