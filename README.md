# Defender Update Tracker

A static dashboard for Microsoft Defender on Windows 11 and Windows Server 2019, 2022 and 2025:

- **Status**: current security intelligence, engine, platform and Sense (MsSense.exe) versions, the download packages, the monthly platform and engine releases with N-2 support, and a fleet compare box.
- **Updates**: Patch Tuesday from the Security Update Guide, exploited vulnerabilities (CISA KEV plus a short hand-kept list), Windows release health known issues, and the Defender update channel settings.
- **Intune and policy**: what the Intune compliance checks actually test (including BitLocker through Device Health Attestation), a policy catalog with OMA-URIs and correct ADMX value strings, an ASR rule value builder, and Intune weekly and in-development notes.
- **Intel**: the detection changelog, new Defender for Endpoint features, a short MsSense / SenseIR explainer, and filtered security news.

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

Microsoft's security intelligence page prints its release time with no time zone (for example `11/15/2026 9:05:12 PM`). On every run the collector compares that clock with the `Last-Modified` header of `mpam-fe.exe` (always GMT) for the same version, and picks UTC or Pacific time accordingly. The result and the evidence are shown under the Security intelligence card.

## Files

| Path | What it is |
| --- | --- |
| `site/` | The published site: `index.html`, `assets/`, `data/` |
| `site/data/pulse.json` | Live data written by the collector |
| `site/data/catalog.json` | Policy catalog, ASR rules, feature notes (edit by hand) |
| `site/data/curated.json` | Hand-kept incidents, references and the Sense fallback (edit by hand) |
| `site/data/link-report.json` | Written by the weekly link check; the page hides hand-kept entries whose link failed |
| `scripts/collect.mjs` | Collector entry point (Node 20+, no npm packages) |
| `scripts/lib/parsers.mjs` | Pure parsers, covered by `test/parsers.test.mjs` |
| `scripts/check-links.mjs` | Checks every hand-kept URL, every curated CVE against MSRC, and that each OMA-URI name appears on its docs page |

## Run locally

```sh
npm test                 # unit tests (no network)
node scripts/collect.mjs # refresh site/data/pulse.json from the live sources
npm run check-links      # link and OMA-URI check
npm run serve            # http://localhost:8080
```

## One-time setup

In the repository settings, open **Pages** and set **Source** to **GitHub Actions**. After that, run **Actions → Refresh data and deploy → Run workflow** once, or wait for the next hourly run.
