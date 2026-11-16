# Defender Update Tracker

A static dashboard for Microsoft Defender on Windows 11 and Windows Server 2019, 2022 and 2025:

- **Status**: current security intelligence, engine, platform and Sense (MsSense.exe) versions, the download packages, the monthly platform and engine releases with N-2 support, and a fleet compare box.
- **Updates**: Patch Tuesday from the Security Update Guide, exploited vulnerabilities (CISA KEV plus a short hand-kept list), Windows release health known issues, Qualys QIDs for the current Patch Tuesday, and the Defender update channel settings.
- **Intune**: what the Intune compliance checks actually test (including BitLocker through Device Health Attestation), Intune weekly and in-development notes, and Microsoft 365 roadmap items for Defender and Intune. Policy values and OMA-URIs are deliberately not included; those are set internally.
- **Intel**: the detection changelog with the last 10 security intelligence versions, public malware hashes checked against Defender's verdict (TweetFeed plus AlienVault OTX, third-party and unvetted) with a hash lookup, new Defender for Endpoint features, a short MsSense / SenseIR explainer, and filtered security news.

It reads only public Microsoft and security sources. It never signs in to a tenant and holds no secrets.

Every release time is shown in UTC and then in US Central time with the correct CST or CDT label.

## How it works

```
GitHub Action (hourly, every 15 min in Patch Tuesday week)
  └─ scripts/collect.mjs  → fetches each source once, writes site/data/pulse.json
       ├─ a failed source keeps its last good data, marked "Stale"
       └─ "What changed" is computed against the last committed snapshot
  └─ commits pulse.json only when content changed, then deploys site/ to GitHub Pages
```

The browser only reads `data/pulse.json`, so the first paint is never empty and never waits on Microsoft.

### The definitions page clock

Microsoft's security intelligence page prints its release time with no time zone (for example `11/15/2026 9:05:12 PM`). It is UTC: on 16 Nov 2026 the page listed a `2:41:33 AM` release at 3:45 AM UTC, which would be in the future if it were Pacific time. The collector re-checks this on every run (the same "not in the future" test, plus the `Last-Modified` header of `mpam-fe.exe` when it is within an hour) and shows the evidence under the Security intelligence card.

## Files

| Path | What it is |
| --- | --- |
| `site/` | The published site: `index.html`, `assets/`, `data/` |
| `site/data/pulse.json` | Live data written by the collector |
| `site/data/features.json` | Reported-but-unconfirmed feature notes (edit by hand) |
| `site/data/curated.json` | Hand-kept incidents, references and the Sense fallback (edit by hand) |
| `site/data/link-report.json` | Written by the weekly link check; the page hides hand-kept entries whose link failed |
| `scripts/collect.mjs` | Collector entry point (Node 20+, no npm packages) |
| `scripts/lib/parsers.mjs` | Pure parsers, covered by `test/parsers.test.mjs` |
| `scripts/inspect-sources.mjs` | Prints live page excerpts to the Actions log (workflow **Inspect sources**), for fixing a parser after Microsoft changes a page |
| `scripts/check-links.mjs` | Checks every hand-kept URL and every curated CVE against MSRC |

## Run locally

```sh
npm test                 # unit tests (no network)
node scripts/collect.mjs # refresh site/data/pulse.json from the live sources
npm run check-links      # link check
npm run serve            # http://localhost:8080
```

## One-time setup

In the repository settings, open **Pages** and set **Source** to **GitHub Actions**. After that, run **Actions → Refresh data and deploy → Run workflow** once, or wait for the next hourly run.
