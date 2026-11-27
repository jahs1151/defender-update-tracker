// Change alerts: "What changed" lines, a webhook payload for Teams, Slack or anything that
// takes JSON, and the static RSS feed. Pure functions only, covered by test/notify.test.mjs.
import { stamp } from "../../site/assets/time.js";

export const SITE_URL = "https://jahs1151.github.io/defender-update-tracker/";

/** One readable line per change: "Security intelligence: 1.463.495.0 → 1.463.497.0". */
export function changeLine(c) {
  if (c.kind === "changed") return `${c.field}: ${c.from} → ${c.to}`;
  if (c.kind === "added") return `${c.field}: new ${c.to}`;
  return `${c.field}: no longer listed ${c.from}`;
}

/** Keep the last `keep` change batches, newest first, adding this run's when content changed. */
export function appendHistory(history = [], pulse, keep = 50) {
  if (!pulse?.changes?.length || pulse.contentChangedAt !== pulse.checkedAt) return history;
  if (history[0]?.at === pulse.checkedAt) return history;
  return [{ at: pulse.checkedAt, lines: pulse.changes.map(changeLine) }, ...history].slice(0, keep);
}

const xml = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[c]);

/** RSS 2.0 feed of change batches. Each item's title names the first change; the body lists all of them. */
export function buildFeed(history = [], site = SITE_URL) {
  const items = history
    .map((h) => {
      const title = h.lines.length > 1 ? `${h.lines[0]} (+${h.lines.length - 1} more)` : h.lines[0] || "Update";
      const body = `<p>Detected ${xml(stamp(h.at))}</p><ul>${h.lines.map((l) => `<li>${xml(l)}</li>`).join("")}</ul>`;
      return `  <item>
    <title>${xml(title)}</title>
    <link>${xml(`${site}#changes`)}</link>
    <guid isPermaLink="false">defender-update-tracker-${xml(h.at)}</guid>
    <pubDate>${new Date(h.at).toUTCString()}</pubDate>
    <description>${xml(body)}</description>
  </item>`;
    })
    .join("\n");
  const built = history[0]?.at ? new Date(history[0].at).toUTCString() : new Date(0).toUTCString();
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>Defender Update Tracker: what changed</title>
  <link>${xml(site)}</link>
  <atom:link href="${xml(`${site}feed.xml`)}" rel="self" type="application/rss+xml"/>
  <description>New Defender security intelligence, engine, platform and Sense builds, Sense issue stages, detection alerts, Patch Tuesday and known-issue changes. Public sources only.</description>
  <language>en-us</language>
  <lastBuildDate>${built}</lastBuildDate>
${items}
</channel>
</rss>
`;
}

/** Which kind of endpoint a webhook URL is, from its host. */
export function webhookKind(url) {
  let host = "";
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return "invalid";
  }
  if (host === "hooks.slack.com") return "slack";
  if (/(?:^|\.)webhook\.office\.com$|(?:^|\.)logic\.azure\.com$|(?:^|\.)powerautomate\.com$|(?:^|\.)powerplatform\.com$/.test(host)) return "teams";
  if (host === "discord.com" || host === "discordapp.com") return "discord";
  return "json";
}

/** The request body for each kind of webhook. */
export function webhookBody(kind, lines, at, site = SITE_URL) {
  const heading = `Defender Update Tracker: ${lines.length} change${lines.length === 1 ? "" : "s"} (${stamp(at)})`;
  const text = `${heading}\n${lines.map((l) => `• ${l}`).join("\n")}\n${site}#changes`;
  if (kind === "slack") return { text };
  if (kind === "discord") return { content: text.slice(0, 1990) };
  if (kind === "teams") {
    // Teams Workflows ("Post to a channel when a webhook request is received") and the older
    // connector webhooks both accept an Adaptive Card wrapped in a message.
    return {
      type: "message",
      attachments: [
        {
          contentType: "application/vnd.microsoft.card.adaptive",
          content: {
            $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
            type: "AdaptiveCard",
            version: "1.4",
            body: [
              { type: "TextBlock", text: heading, weight: "Bolder", wrap: true },
              ...lines.map((l) => ({ type: "TextBlock", text: `• ${l}`, wrap: true, spacing: "Small" })),
            ],
            actions: [{ type: "Action.OpenUrl", title: "Open the tracker", url: `${site}#changes` }],
          },
        },
      ],
    };
  }
  return { source: "defender-update-tracker", at, text, changes: lines, url: `${site}#changes` };
}
