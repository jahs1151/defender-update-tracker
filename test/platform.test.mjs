// Windows-only filtering: detection names, file types, headlines.
import { test } from "node:test";
import assert from "node:assert/strict";
import { platformOf, isWindowsDetection, windowsRows, fileTypePlatform, taggedNonWindows, nonWindowsTitle } from "../scripts/lib/platform.mjs";
import { updateDetectionIndex, updateFamilyIndex, firstSeenByBuild, detectionAlerts, parseEncyclopediaResults } from "../scripts/lib/threats.mjs";
import { vtPlatform } from "../scripts/lib/virustotal.mjs";
import { parseIntuneWhatsNew, filterRoadmap } from "../scripts/lib/parsers.mjs";

test("platform of a detection name", () => {
  assert.equal(platformOf("Behavior:Linux/LinPeas.H"), "Linux");
  assert.equal(platformOf("Trojan:Win32/Wacatac.B!ml"), "Win32");
  assert.equal(platformOf("Program:MacOS_X/Multiverze"), "MacOS_X");
  assert.equal(platformOf("SomethingWithoutPlatform"), "");
});

test("non-Windows detection names are dropped", () => {
  for (const n of ["Behavior:Linux/LinPeas.H", "Trojan:MacOS/Multiverze!rfn", "Program:MacOS_X/Foo", "Trojan:OSX/Bar", "Trojan:AndroidOS/Joker.A", "Trojan:iPhoneOS/X.A", "Trojan:Unix/Mirai.A", "Backdoor:PHP/Webshell.PA", "Trojan:Perl/X", "Backdoor:SH/Y", "Trojan:FreeBSD/Z"]) assert.equal(isWindowsDetection(n), false, n);
});

test("Windows and cross-platform script detection names are kept", () => {
  for (const n of ["Trojan:Win32/Wacatac.B!ml", "Trojan:Win64/AcrStealer!rfn", "Trojan:MSIL/Remcos!rfn", "Trojan:O97M/Casdet!rfn", "TrojanDownloader:W97M/X", "Trojan:X97M/Y", "Trojan:VBA/Z", "Trojan:VBS/Emotet!rfn", "Trojan:JS/Foo", "Trojan:PowerShell/VinciRat.EF!MTB", "Trojan:Python/PolinRider.A!HN", "Trojan:Script/Multiverze!rfn", "Trojan:HTML/Phish", "Trojan:BAT/Salatloader.PS!MTB", "Trojan:LNK/Foo", "Trojan:HTA/Bar", "Backdoor:ASP/Webshell.A", "Trojan:WinNT/Foo", "Trojan:Java/Foo", "Trojan:PDF/Foo", "Trojan:NPM/Foo", "NoPlatformName"]) assert.equal(isWindowsDetection(n), true, n);
  assert.deepEqual(windowsRows([{ name: "Trojan:Linux/A" }, { name: "Trojan:Win32/B" }]).map((r) => r.name), ["Trojan:Win32/B"]);
});

test("the detection and family indexes hold no non-Windows names, and old ones are cleaned", () => {
  const rows = [{ name: "Behavior:Linux/LinPeas.H", change: "added" }, { name: "Trojan:Win32/Berbew!rfn", change: "added" }, { name: "Trojan:AndroidOS/Joker.A", change: "added" }];
  const now = new Date("2026-11-28T12:00:00Z");
  const old = { "1.0.0.1": { releasedAt: "2026-11-27T00:00:00Z", names: ["Trojan:MacOS/Old.A", "Trojan:Win32/Keep.A"] } };
  const idx = updateDetectionIndex(old, [{ version: "1.0.0.2", releasedAt: "2026-11-28T00:00:00Z", rows }], 30, now);
  assert.deepEqual(idx["1.0.0.2"].names, ["Trojan:Win32/Berbew!rfn"]);
  assert.deepEqual(idx["1.0.0.1"].names, ["Trojan:Win32/Keep.A"]);
  const fam = updateFamilyIndex({ linpeas: { family: "LinPeas", first: "x", firstAt: "2026-11-27T00:00:00Z", last: "x", lastAt: "2026-11-27T00:00:00Z", names: ["Behavior:Linux/LinPeas.H"] } }, [{ version: "1.0.0.2", releasedAt: "2026-11-28T00:00:00Z", rows }], 90, now);
  assert.equal(fam.linpeas, undefined);
  assert.ok(fam.berbew);
  assert.equal(fam.joker, undefined);
  assert.deepEqual(firstSeenByBuild([{ version: "1.0.0.2", rows }], fam), { "1.0.0.2": ["Trojan:Win32/Berbew!rfn"] });
  const alerts = detectionAlerts([{ version: "1.0.0.2", releasedAt: now.toISOString(), rows }], [{ title: "LinPeas and Berbew spread", url: "u", source: "s", names: ["LinPeas", "Berbew"], published: now.toISOString() }], { now });
  assert.deepEqual(alerts.map((a) => a.detection), ["Trojan:Win32/Berbew!rfn"]);
});

test("encyclopedia names for other platforms are not used", () => {
  const html = "<p>3 entries found</p> Trojan:Linux/Valley.A Trojan:Win32/Valley.B Trojan:AndroidOS/Valley.C";
  assert.deepEqual(parseEncyclopediaResults(html, "ValleyRAT").names, ["Trojan:Win32/Valley.B"]);
  assert.deepEqual(parseEncyclopediaResults("<p>2 entries found</p> Trojan:Linux/Remus.A Trojan:Win32/Remus.B", "Remus").names, ["Trojan:Win32/Remus.B"]);
});

test("file types: Windows kept, Android, ELF, Mach-O and iOS dropped, archives undecided", () => {
  for (const t of ["Win32 EXE", "Win32 DLL", "Windows Installer", "Windows shortcut", "PowerShell", "JavaScript", "VBScript", "HTML", "MS Word Document", "Office Open XML Excel"]) assert.equal(fileTypePlatform(t), "windows", t);
  for (const t of ["Android", "ELF", "Mach-O", "iOS App", "Bourne-Again shell script"]) assert.equal(fileTypePlatform(t), "other", t);
  for (const t of ["ZIP", "RAR", "7-Zip", "ISO", "", "unknown"]) assert.equal(fileTypePlatform(t), "unknown", t);
  assert.equal(taggedNonWindows("#apk #malware"), true);
  assert.equal(taggedNonWindows("#exe #stealer"), false);
});

test("VirusTotal platform uses the file type first", () => {
  assert.equal(vtPlatform({ type_description: "ELF", type_tag: "elf" }), "other");
  assert.equal(vtPlatform({ type_description: "Mach-O", type_tag: "macho" }), "other");
  assert.equal(vtPlatform({ type_description: "Android", type_tag: "android" }), "other");
  assert.equal(vtPlatform({ type_description: "Win32 EXE", type_tag: "peexe" }), "windows");
  assert.equal(vtPlatform({ type_description: "Windows shortcut", type_tag: "lnk" }), "windows");
  assert.equal(vtPlatform({ type_description: "ZIP", type_tag: "zip" }), "unknown");
  assert.equal(vtPlatform({ type_description: "ZIP", type_tag: "zip", tags: ["contains-lnk"] }), "windows");
});

test("headlines and feature titles about another OS are dropped, Windows ones stay", () => {
  assert.equal(nonWindowsTitle("Recovery Lock management for macOS"), true);
  assert.equal(nonWindowsTitle("New Linux antivirus settings for Microsoft Defender for Endpoint"), true);
  assert.equal(nonWindowsTitle("GhostMap: The Android flaw that crashes your phone"), true);
  assert.equal(nonWindowsTitle("Enrollment for iOS/iPadOS ADE"), true);
  assert.equal(nonWindowsTitle("Custom compliance scripts on Windows and macOS"), false);
  assert.equal(nonWindowsTitle("Microsoft Defender Antivirus update"), false);
  const road = filterRoadmap([{ id: 1, title: "Microsoft Intune: Recovery Lock for macOS" }, { id: 2, title: "Microsoft Intune: Windows autopatch" }]);
  assert.deepEqual(road.map((r) => r.id), ["2"]);
  const html = `<h2>Week of November 17, 2026</h2><h3 id="a">New Linux antivirus settings for Defender</h3><p>Windows and Linux devices can use Defender antivirus.</p><h3 id="b">Windows compliance update</h3><p>Windows compliance.</p>`;
  assert.deepEqual(parseIntuneWhatsNew(html, "https://x")[0].items.map((i) => i.id), ["b"]);
});
