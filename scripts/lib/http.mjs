// fetch wrappers with timeout and retry with backoff.

export const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/** Last-Modified header of every URL fetched this run, for the Source health list. */
export const lastModifiedSeen = new Map();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function request(url, { timeoutMs = 20000, retries = 2, accept = "*/*", method = "GET", headers = {}, redirect = "follow" } = {}) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const res = await fetch(url, {
        method,
        redirect,
        headers: { "user-agent": UA, accept, "accept-language": "en-US,en;q=0.9", ...headers },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status >= 500 || res.status === 429) throw new Error(`HTTP ${res.status}`);
      if (res.ok) lastModifiedSeen.set(url, res.headers.get("last-modified") || "");
      return res;
    } catch (error) {
      lastError = error;
      if (attempt < retries) await sleep(1500 * 2 ** attempt);
    }
  }
  throw lastError;
}

export async function getText(url, opts = {}) {
  const res = await request(url, { accept: "text/html,application/xhtml+xml,application/xml,application/rss+xml,*/*", ...opts });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

export async function getJson(url, opts = {}) {
  const res = await request(url, { accept: "application/json", ...opts });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/** Follow redirects by hand so we can read the final download URL and its headers. */
export async function resolveDownload(start) {
  let current = start;
  for (let hop = 0; hop < 6; hop += 1) {
    const res = await request(current, { method: "HEAD", redirect: "manual", timeoutMs: 15000 });
    const location = res.headers.get("location");
    if (location && res.status >= 300 && res.status < 400) {
      current = new URL(location, current).toString();
      continue;
    }
    return {
      url: new URL(current),
      lastModified: res.headers.get("last-modified") || "",
      bytes: Number(res.headers.get("content-length") || 0),
    };
  }
  return { url: new URL(current), lastModified: "", bytes: 0 };
}

export function errorText(error) {
  if (error && error.name === "TimeoutError") return "Timed out";
  return (error && error.message ? error.message : String(error)).slice(0, 160);
}
