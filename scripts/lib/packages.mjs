// Read what is inside the Defender download packages using HTTP range requests,
// so the collector never downloads the whole file.
import { createInflateRaw } from "node:zlib";
import { UA } from "./http.mjs";

async function rangeBytes(url, start, end) {
  const res = await fetch(url, {
    headers: { "user-agent": UA, range: `bytes=${start}-${end}` },
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok && res.status !== 206) throw new Error(`HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

function inflateSome(data) {
  return new Promise((resolve) => {
    const parts = [];
    const stream = createInflateRaw();
    stream.on("data", (c) => parts.push(c));
    stream.on("error", () => resolve(Buffer.concat(parts)));
    stream.on("end", () => resolve(Buffer.concat(parts)));
    stream.end(data);
  });
}

function dosDate(value) {
  const year = ((value >> 9) & 0x7f) + 1980;
  const month = (value >> 5) & 0x0f;
  const day = value & 0x1f;
  if (year < 2000 || month < 1 || month > 12 || day < 1 || day > 31) return "";
  return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

const KEY_FILES = ["mpengine.dll", "mpasbase.vdm", "mpasdlta.vdm", "mpavbase.vdm", "mpavdlta.vdm", "MsMpEng.exe", "MpSvc.dll", "WdFilter.sys"];

/** Parse a cabinet header found inside an .exe: key file names and the first file date. */
export function cabFacts(buf) {
  const at = buf.indexOf(Buffer.from("MSCF"));
  if (at < 0) return { files: [], fileDate: "" };
  const cab = buf.subarray(at);
  const cFiles = cab.readUInt16LE(28);
  let pos = cab.readUInt32LE(16);
  const files = [];
  let fileDate = "";
  for (let n = 0; n < cFiles && pos + 18 < cab.length; n += 1) {
    const date = cab.readUInt16LE(pos + 10);
    pos += 16;
    const end = cab.indexOf(0, pos);
    if (end < 0) break;
    const name = cab.subarray(pos, end).toString("utf8");
    pos = end + 1;
    if (!fileDate) fileDate = dosDate(date);
    const base = name.split(/[/\\]/).pop();
    if (KEY_FILES.some((k) => k.toLowerCase() === base.toLowerCase()) && !files.includes(base)) files.push(base);
  }
  return { files, fileDate };
}

export async function exeContents(url) {
  return cabFacts(await rangeBytes(url, 0, 519_999));
}

/** Platform version folder inside defender-dism-x64.cab in the offline image zip. */
export async function wimPlatform(zipUrl, totalBytes) {
  const len = totalBytes;
  if (!len) return "";
  const tailStart = Math.max(0, len - 65536);
  const tail = await rangeBytes(zipUrl, tailStart, len - 1);
  const eocd = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0) return "";
  const cdSize = tail.readUInt32LE(eocd + 12);
  const cdOff = tail.readUInt32LE(eocd + 16);
  const cd = cdOff >= tailStart ? tail.subarray(cdOff - tailStart, cdOff - tailStart + cdSize) : await rangeBytes(zipUrl, cdOff, cdOff + cdSize - 1);
  let local = -1;
  let nameLen = 0;
  for (let i = 0; i + 46 <= cd.length && cd.readUInt32LE(i) === 0x02014b50; ) {
    const nlen = cd.readUInt16LE(i + 28);
    const elen = cd.readUInt16LE(i + 30);
    const clen = cd.readUInt16LE(i + 32);
    const name = cd.subarray(i + 46, i + 46 + nlen).toString("utf8");
    if (name.endsWith("defender-dism-x64.cab")) {
      local = cd.readUInt32LE(i + 42);
      nameLen = nlen;
      break;
    }
    i += 46 + nlen + elen + clen;
  }
  if (local < 0) return "";
  const head = await rangeBytes(zipUrl, local, local + 30 + nameLen + 1_200_000);
  const extra = head.readUInt16LE(28);
  const inflated = await inflateSome(head.subarray(30 + head.readUInt16LE(26) + extra));
  return /Platform\\(\d+\.\d+\.\d+\.\d+)/.exec(inflated.toString("latin1"))?.[1] ?? "";
}
