// Small HTML/XML text helpers. No dependencies, so the Action needs no npm install.

export function plain(value = "") {
  let text = String(value);
  for (let pass = 0; pass < 3; pass += 1) {
    const next = text
      .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
      .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
      .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&quot;/gi, '"')
      .replace(/&#39;|&apos;/gi, "'")
      .replace(/&nbsp;/gi, " ")
      .replace(/&amp;/gi, "&");
    if (next === text) break;
    text = next;
  }
  return text
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function tag(block, name) {
  const cdata = new RegExp(`<${name}[^>]*>\\s*<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>\\s*</${name}>`, "i").exec(block);
  if (cdata) return cdata[1].trim();
  const m = new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, "i").exec(block);
  return m ? m[1].trim() : "";
}

export function matchAfter(text, anchor, value, span = 200) {
  const at = anchor.exec(text);
  if (!at) return "";
  const m = value.exec(text.slice(at.index, at.index + span));
  return m ? m[0] : "";
}

export function slug(value = "") {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 80);
}

export function toIso(value) {
  if (!value) return "";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

const VERSION = /\b\d+\.\d+\.\d+\.\d+\b/;
export const isVersion = (v) => typeof v === "string" && VERSION.test(v);

export function osTags(text) {
  const tags = new Set();
  if (/windows 11|\b2[45]h2\b|\b26h[12]\b/i.test(text)) tags.add("win11");
  if (/server 2019/i.test(text)) tags.add("srv2019");
  if (/server 2022/i.test(text)) tags.add("srv2022");
  if (/server 2025/i.test(text)) tags.add("srv2025");
  if (tags.size === 0 || (/windows server/i.test(text) && ![...tags].some((t) => t.startsWith("srv")))) {
    if (/windows server/i.test(text)) ["srv2019", "srv2022", "srv2025"].forEach((t) => tags.add(t));
  }
  if (tags.size === 0) ["win11", "srv2019", "srv2022", "srv2025"].forEach((t) => tags.add(t));
  return [...tags];
}
