#!/usr/bin/env node
// Post this run's "What changed" lines to the webhook in the ALERT_WEBHOOK_URL secret.
// Does nothing when the secret is not set, or when this run found no change.
// Never fails the workflow: a webhook problem is logged as a warning.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { changeLine, webhookKind, webhookBody } from "./lib/notify.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const url = (process.env.ALERT_WEBHOOK_URL || "").trim();

async function main() {
  if (!url) {
    console.log("ALERT_WEBHOOK_URL is not set. No alert sent.");
    return;
  }
  const pulse = JSON.parse(await readFile(join(root, "site", "data", "pulse.json"), "utf8"));
  if (pulse.contentChangedAt !== pulse.checkedAt || !pulse.changes?.length) {
    console.log("Nothing changed on this run. No alert sent.");
    return;
  }
  const kind = webhookKind(url);
  if (kind === "invalid" || !url.startsWith("https://")) {
    console.log("::warning::ALERT_WEBHOOK_URL is not an https URL. No alert sent.");
    return;
  }
  const lines = pulse.changes.map(changeLine);
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": "defender-update-tracker" },
    body: JSON.stringify(webhookBody(kind, lines, pulse.checkedAt)),
    redirect: "manual",
    signal: AbortSignal.timeout(15000),
  });
  // The URL is a secret: log only the kind and status, never the URL.
  if (res.status >= 200 && res.status < 300) console.log(`Sent ${lines.length} change line(s) to the ${kind} webhook (HTTP ${res.status}).`);
  else console.log(`::warning::The ${kind} webhook answered HTTP ${res.status}. No retry.`);
}

main().catch((error) => console.log(`::warning::Alert webhook failed: ${error.name === "TimeoutError" ? "timed out" : error.message}`));
