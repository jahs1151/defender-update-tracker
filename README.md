# Defender Update Tracker

A static dashboard for Microsoft Defender on Windows 11 and Windows Server 2019, 2022 and 2025. **Windows only**: detections, files, headlines and feature items for Linux, macOS, Android and iOS are left out (see "Windows-only filtering" below).


- **Status**: current security intelligence, engine, platform and Sense (MsSense.exe) versions, the download packages, the monthly platform and engine releases with N-2 support, and a version compare box.
- **Updates**: Patch Tuesday from the Security Update Guide, exploited vulnerabilities (CISA KEV plus a short hand-kept list), Windows release health known issues, Qualys QIDs for the current Patch Tuesday, and the Defender update channel settings.
- **Intune**: what the Intune compliance checks actually test (including BitLocker through Device Health Attestation), Intune weekly and in-development notes, and Microsoft 365 roadmap items for Defender and Intune. Policy values and OMA-URIs are not included.
- **Intel**: the detection changelog with the last 10 security intelligence versions, public malware hashes checked against Defender's verdict (TweetFeed plus AlienVault OTX, third-party and unvetted) with a hash lookup, new Defender for Endpoint features, a short MsSense / SenseIR explainer, and filtered security news.

- **Sense**: every Sense (MsSense.exe) release seen in the Update Catalog with its OS scope, restart requirement and ring; the KB5005292 known-issues and restart text; and each reported Sense problem tracked through four stages (Community reports, Microsoft acknowledged, Fix announced, Fix published).
- **Alerts**: after each refresh that changes something, the "What changed" lines go to `feed.xml` (RSS) and, if the `ALERT_WEBHOOK_URL` secret is set, to a Teams, Slack, Discord or plain JSON webhook. The Detections tab (`#threats`) shows each build's detections with search, a Windows-families filter, new and removed names, JSON and CSV export and a per-build chart, plus **detection alerts**, **threat coverage**, newly exploited **CISA KEV** CVEs and **public hashes** (a new security intelligence build added a detection for a threat named in the news) and **vendor threat coverage** (threats named by CrowdStrike, SentinelOne, Sophos, Bitdefender, ESET, Trend Micro, Unit 42, eSentire, AhnLab ASEC, watchTowr, Check Point Research and Symantec research and by The Hacker News, BleepingComputer and SecurityWeek headlines, marked Yes, Unclear or Lookup failed, retrying). Matching uses a 30-day index of every detection changelog version (`site/data/detections.json`) and Microsoft's malware encyclopedia.
- **VirusTotal**: set the repository secret `VIRUSTOTAL_API_KEY` to check the public hashes on VirusTotal (at most 4 lookups a minute and 500 a day, each answer kept 24 hours). Without it the page says "VirusTotal key not set". The key is read from the environment only and never logged or written to the data files.

A search box at the top searches CVEs, KBs, Qualys QIDs, features and news across all tabs. It reads only public Microsoft and security sources and holds no secrets.

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

## Change alerts

Add a repository secret named `ALERT_WEBHOOK_URL` (Settings → Secrets and variables → Actions). The refresh workflow posts to it only when content changed, and does nothing if the secret is missing. The format is picked from the host: `hooks.slack.com` gets Slack text, `*.webhook.office.com` and `*.logic.azure.com` (Teams Workflows) get an Adaptive Card, `discord.com` gets Discord text, anything else gets JSON `{ text, changes, at, url }`. For email, point it at a Power Automate or Zapier webhook that forwards to a mailbox. The RSS feed needs no setup: `https://jahs1151.github.io/defender-update-tracker/feed.xml`.

## Sense issues and threat matching

Sense issues are seeded by hand in `site/data/curated.json` (`senseIssues`); the collector only ever moves them forward. Detection alerts and vendor coverage match a threat name to a Defender detection family only when the two are the same name (letters and digits, ignoring case); generic families such as Wacatac or Agent never match, and anything not settled is "Unclear". `site/data/families.json` keeps 90 days of detection families seen in the changelog.

## Run locally

```sh
npm test                 # unit tests (no network)
node scripts/collect.mjs # refresh site/data/pulse.json from the live sources
npm run check-links      # link check
npm run serve            # http://localhost:8080
```

## One-time setup

In the repository settings, open **Pages** and set **Source** to **GitHub Actions**. After that, run **Actions → Refresh data and deploy → Run workflow** once, or wait for the next hourly run.

## Windows-only filtering

The rules live in `scripts/lib/platform.mjs` and are covered by `test/platform.test.mjs`.

**Detection names** (`Type:Platform/Family`) are judged by the platform part.

- Dropped: `Linux`, `MacOS`, `MacOS_X`, `OSX`, `Mac`, `AndroidOS`, `Android`, `iOS`, `iPhoneOS`, `iPadOS`, `Unix`, `FreeBSD`, `BSD`, `Solaris`, `AIX`, `SH`, `Bash`, `ELF`, `SymbOS`, and the Unix-side server scripts `PHP`, `Perl` and `Ruby`.
- Kept: `Win32`, `Win64`, `WinNT`, `Win16`, `MSIL`, `VBS`, `VBA`, `JS`, `HTA`, `PowerShell`, `BAT`, `INF`, `LNK`, `ASP`, `O97M`, `X97M`, `W97M`, `HTML`, `Script`, `XML`, `Python`, `AutoIt`, `ALisp`, and the cross-platform formats `Java`, `PDF`, `SWF`, `NPM` and `PyPI`, which run on Windows too. A name with no platform part is kept.
- Applied when each changelog page is read, so the per-build files, `detections.json`, `families.json`, alerts, coverage rows, "notable new detections" and the encyclopedia lookups never hold a non-Windows name. Data saved before the rule is cleaned on the next run. The browser repeats the check.

**VirusTotal and public hashes** (no extra lookups are spent):

- TweetFeed posts tagged `#android`, `#apk`, `#linux`, `#elf`, `#mirai`, `#macos` and similar are skipped before any lookup.
- A saved file type (OTX or VirusTotal) that says Android, ELF, Mach-O, iOS or shell script is skipped before a VirusTotal lookup.
- After a lookup, VirusTotal's file type decides first (kept: Win32 EXE, DLL, Windows Installer, Windows shortcut, scripts, Office documents, HTML; dropped: Android, ELF, Mach-O, iOS). Archives (ZIP, RAR, 7z, ISO) are judged by VirusTotal's tags and by what the engines call the file, so a ZIP holding a shortcut stays and a ZIP holding an Android dropper goes. An archive with no clear contents stays, because it cannot be shown to be non-Windows.
- Dropped hashes are remembered in `excluded` so they are not picked again.

**Other text**: Intune and roadmap items and vendor, news and community headlines whose title is about macOS, iOS, Android or Linux and not Windows are left out.
