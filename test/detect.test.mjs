import { test } from "node:test";
import assert from "node:assert/strict";
import { compactName, findDetections, indexWindow, firstListing, notFoundText, detectionHandlers } from "../site/assets/detect.js";

const versions = {
  "1.463.503.0": { releasedAt: "2026-11-28T00:03:03.000Z", names: ["Trojan:Win32/Wacatac.B!ml", "Trojan:Python/PolinRider.A!HN"] },
  "1.463.500.0": { releasedAt: "2026-11-27T20:00:00.000Z", names: ["Trojan:Win32/Wacatac.B!ml", "HackTool:MSIL/Spoofer!rfn", "Trojan:VBA/Obfuse!AMTB"] },
  "1.463.510.0": { releasedAt: "2026-11-28T13:07:37.000Z", names: ["Trojan:Win32/Wacatac.C!ml", "Trojan:Win32/Wacatac.B!ml"] },
  "1.463.400.0": { releasedAt: "2026-11-20T00:00:00.000Z", names: ["Backdoor:Win32/Berbew!rfn"] },
};

test("compactName ignores case, spaces and punctuation", () => {
  assert.equal(compactName("Trojan:Win32/Wacatac.B!ml"), "trojanwin32wacatacbml");
  assert.equal(compactName("  wacatac b ml "), "wacatacbml");
});

test("first listing is the oldest build, not the order of the index", () => {
  const r = findDetections(versions, "Wacatac.B!ml");
  assert.equal(r.total, 1);
  const m = r.matches[0];
  assert.equal(m.name, "Trojan:Win32/Wacatac.B!ml");
  assert.equal(m.first.version, "1.463.500.0");
  assert.equal(m.last.version, "1.463.510.0");
  assert.equal(m.count, 3);
  assert.deepEqual(m.builds.map((b) => b.version), ["1.463.500.0", "1.463.503.0", "1.463.510.0"]);
});

test("matching is case-insensitive, partial, and tolerant of ! and spaces", () => {
  for (const q of ["wacatac.b", "WACATAC B ML", "Trojan:Win32/Wacatac", "wacatacbml", "win32/wacatac.b!ml"]) assert.ok(findDetections(versions, q).matches.some((m) => m.name === "Trojan:Win32/Wacatac.B!ml"), q);
  assert.equal(findDetections(versions, "Wacatac").total, 2);
  assert.equal(findDetections(versions, "spoofer").matches[0].name, "HackTool:MSIL/Spoofer!rfn");
  assert.equal(findDetections(versions, "Trojan:VBA/Obfuse!AMTB").matches[0].first.version, "1.463.500.0");
});

test("exact match ranks first, short queries are refused, misses return nothing", () => {
  const r = findDetections(versions, "Trojan:Win32/Wacatac.B!ml");
  assert.equal(r.matches[0].name, "Trojan:Win32/Wacatac.B!ml");
  const t = findDetections(versions, "ab");
  assert.equal(t.tooShort, true);
  assert.equal(findDetections(versions, "LinPeas").total, 0);
  assert.equal(findDetections(versions, "x", { minLength: 1 }).tooShort, false);
});

test("the window says how far back the data goes", () => {
  const w = indexWindow(versions);
  assert.equal(w.builds, 4);
  assert.equal(w.oldest, "1.463.400.0");
  assert.equal(w.newest, "1.463.510.0");
  assert.equal(w.from.slice(0, 10), "2026-11-20");
  const text = notFoundText("LinPeas", w);
  assert.match(text, /No Windows detection matching "LinPeas"/);
  assert.match(text, /4 builds from 1\.463\.400\.0 \(2026-11-20\) to 1\.463\.510\.0 \(2026-11-28\)/);
  assert.match(notFoundText("Trojan:Linux/Mirai", w), /Windows only/);
});

test("added, updated or just listed", () => {
  const m = findDetections(versions, "Spoofer").matches[0];
  assert.equal(firstListing(m, { "1.463.500.0": "added" }).label, "Added in");
  assert.match(firstListing(m, { "1.463.500.0": "updated" }).label, /as an update/);
  assert.equal(firstListing(m, {}).kind, "listed");
});

test("Enter, Go and Search on a phone keyboard run the search", () => {
  const ran = [];
  const timers = [];
  const h = detectionHandlers((q) => ran.push(q), { setTimer: (fn) => timers.push(fn) || timers.length, clearTimer: () => {} });
  let prevented = 0;
  let blurred = 0;
  const input = { id: "det-q", value: "Wacatac", blur: () => (blurred += 1) };
  const form = { id: "det-form", querySelector: () => input };
  // Form submit (what the mobile Go/Search key fires)
  assert.equal(h.onSubmit({ target: form, preventDefault: () => (prevented += 1) }), true);
  // Enter keydown inside the input (keyboards that do not submit the form)
  assert.equal(h.onKeydown({ target: input, key: "Enter", preventDefault: () => (prevented += 1) }), true);
  assert.equal(h.onKeydown({ target: input, key: "a", preventDefault: () => {} }), false);
  assert.deepEqual(ran, ["Wacatac", "Wacatac"]);
  assert.equal(prevented, 2);
  assert.equal(blurred, 2);
  // Live search while typing runs after the delay
  h.onInput({ target: { id: "det-q", value: "spoof" } });
  assert.equal(ran.length, 2);
  timers[0]();
  assert.deepEqual(ran.at(-1), "spoof");
  // Other forms and fields are ignored
  assert.equal(h.onSubmit({ target: { id: "search-form" }, preventDefault: () => {} }), false);
  assert.equal(h.onInput({ target: { id: "other" } }), false);
});
