import { test } from "node:test";
import assert from "node:assert/strict";
import { cabFacts } from "../scripts/lib/packages.mjs";

// Build a minimal cabinet: 36-byte header, one folder entry, then CFFILE entries.
function cab(files) {
  const header = Buffer.alloc(36);
  header.write("MSCF", 0, "latin1");
  const folder = Buffer.alloc(8);
  const entries = files.map(([name, y, m, d]) => {
    const e = Buffer.alloc(16);
    e.writeUInt16LE(((y - 1980) << 9) | (m << 5) | d, 10);
    return Buffer.concat([e, Buffer.from(`${name}\0`, "latin1")]);
  });
  header.writeUInt32LE(36 + 8, 16); // coffFiles
  header.writeUInt16LE(1, 26); // cFolders
  header.writeUInt16LE(files.length, 28); // cFiles
  return Buffer.concat([Buffer.from("MZ stub before the cabinet "), header, folder, ...entries, Buffer.alloc(32)]);
}

test("cabinet file list and date", () => {
  const facts = cabFacts(cab([["mpengine.dll", 2026, 11, 10], ["readme.txt", 2026, 11, 10], ["mpasbase.vdm", 2026, 11, 15]]));
  assert.deepEqual(facts, { files: ["mpengine.dll", "mpasbase.vdm"], fileDate: "2026-11-10" });
  assert.deepEqual(cabFacts(Buffer.from("no cabinet here")), { files: [], fileDate: "" });
});
