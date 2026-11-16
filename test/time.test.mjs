import { test } from "node:test";
import assert from "node:assert/strict";
import { stamp, parseUsClock, chicagoZone, patchWindow, cmpVersion } from "../site/assets/time.js";

test("winter time shows CST, six hours behind UTC", () => {
  assert.equal(stamp("2026-11-15T23:50:00Z"), "15 Nov 2026, 23:50 UTC · 15 Nov 2026, 17:50 CST");
});

test("summer time shows CDT, five hours behind UTC", () => {
  assert.equal(stamp("2026-07-15T23:50:00Z"), "15 Jul 2026, 23:50 UTC · 15 Jul 2026, 18:50 CDT");
});

test("late-evening Chicago release keeps the Chicago date", () => {
  assert.equal(stamp("2026-11-16T03:10:00Z"), "16 Nov 2026, 03:10 UTC · 15 Nov 2026, 21:10 CST");
});

test("DST boundaries", () => {
  assert.equal(chicagoZone(new Date("2026-03-08T07:59:00Z")), "CST");
  assert.equal(chicagoZone(new Date("2026-03-08T08:00:00Z")), "CDT");
  assert.equal(chicagoZone(new Date("2026-11-01T06:59:00Z")), "CDT");
  assert.equal(chicagoZone(new Date("2026-11-01T07:00:00Z")), "CST");
});

test("unparseable values say the time was not published", () => {
  assert.equal(stamp("not a date"), "Time not published");
  assert.equal(stamp(""), "Time not published");
});

test("date-only values are labelled, not given a fake time", () => {
  assert.equal(stamp("2026-11-10"), "10 Nov 2026 (date only)");
});

test("Microsoft US clock parses as UTC or Pacific", () => {
  assert.equal(parseUsClock("11/15/2026 11:50:45 PM", "UTC").toISOString(), "2026-11-15T23:50:45.000Z");
  assert.equal(parseUsClock("11/15/2026 11:50:45 PM", "America/Los_Angeles").toISOString(), "2026-11-16T07:50:45.000Z");
  assert.equal(parseUsClock("7/1/2026 12:05:00 AM", "America/Los_Angeles").toISOString(), "2026-07-01T07:05:00.000Z");
  assert.equal(parseUsClock("garbage"), null);
});

test("Patch Tuesday window", () => {
  const p = patchWindow(new Date("2026-11-16T03:00:00Z"));
  assert.equal(p.last, "2026-11-10");
  assert.equal(p.next, "2026-12-08");
  assert.equal(p.inWindow, true);
  assert.equal(patchWindow(new Date("2026-11-09T00:00:00Z")).next, "2026-11-10");
});

test("version compare is numeric", () => {
  assert.ok(cmpVersion("4.18.26100.4", "4.18.25110.5") > 0);
  assert.ok(cmpVersion("1.1.9.0", "1.1.10.0") < 0);
  assert.equal(cmpVersion("1.2.3.4", "1.2.3.4"), 0);
});
