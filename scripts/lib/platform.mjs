// Windows-only filtering. The tracker covers Microsoft Defender on Windows 11 and Windows Server, so
// detections and files for other operating systems are dropped before they reach the data files.
// Pure functions, covered by test/platform.test.mjs.
//
// Detection names look like "Type:Platform/Family.Variant!suffix". The platform token decides.
//
// DROPPED: the operating system or runtime is not Windows.
//   Linux, MacOS, MacOS_X, OSX, Mac, AndroidOS, Android, iOS, iPhoneOS, iPadOS, Unix, FreeBSD, BSD,
//   Solaris, AIX, SH, Bash, ELF, SymbOS, plus server-side scripts that are written for Unix web
//   hosts: PHP, Perl, Ruby.
// KEPT: everything else, including Win32, Win64, WinNT, Win16, MSIL, VBS, VBA, JS, HTA, PowerShell,
//   BAT, INF, LNK, ASP, O97M, X97M, W97M, HTML, Script, XML, Python, AutoIt, ALisp and the
//   cross-platform formats Java, PDF, SWF and the NPM and PyPI package families, because those run on
//   Windows too and a name with no platform token cannot be shown to be anything else.

const NON_WINDOWS_PLATFORMS = new Set(
  [
    "linux", "macos", "macos_x", "macosx", "osx", "mac", "androidos", "android", "ios", "iphoneos", "ipados", "unix", "freebsd", "bsd",
    "solaris", "aix", "sh", "bash", "elf", "symbos", "php", "perl", "ruby",
  ],
);

/** "Behavior:Linux/LinPeas.H" -> "Linux". "" when the name has no Type:Platform/ part. */
export function platformOf(name = "") {
  const m = /^[^:\/]+:([^\/]+)\//.exec(String(name).trim());
  return m ? m[1] : "";
}

/** True for every detection name except those for a non-Windows platform. */
export function isWindowsDetection(name = "") {
  const p = platformOf(name).toLowerCase().replace(/[\s-]/g, "_");
  return !NON_WINDOWS_PLATFORMS.has(p) && !NON_WINDOWS_PLATFORMS.has(p.replace(/_/g, ""));
}

/** Changelog rows ({ name, ... }) without the non-Windows detections. */
export const windowsRows = (rows = []) => rows.filter((r) => isWindowsDetection(r?.name));

// ---------- files (VirusTotal, OTX, TweetFeed tags) ----------

/** Words in a type, tag or engine name that mark a file as not for Windows. */
export const NON_WINDOWS_WORDS = /\b(?:android|androidos|andr|apk|dex|linux|elf|mirai|gafgyt|macos|osx|mach-?o|macho|ios|iphoneos|ipa|unix|shell script|bash|php|perl)\b/i;
const WINDOWS_WORDS = /\b(?:win(?:32|64|dows)?|msil|lnk|pe32|pe64|peexe|pedll|dll|vbs|vba|o97m|powershell|ps1|bat|cmd|js|jscript|hta|html|msi|w97m|x97m)\b/i;

/**
 * What a file type description or type tag says about the platform: "windows", "other" or "unknown".
 *   windows: PE exe/dll/sys, MSI, LNK, ps1/vbs/js/hta/bat/cmd scripts, Office documents, HTML.
 *   other:   Android (APK, DEX), ELF, Mach-O, iOS (IPA), shell scripts.
 *   unknown: archives (ZIP, RAR, 7z, ISO) and anything else, until the contents say which.
 */
export function fileTypePlatform(type = "") {
  const t = String(type).replace(/[-_]/g, " ");
  if (!t.trim()) return "unknown";
  if (/\b(?:android|apk|dex|elf|mach ?o|macho|ios|ipa|shell script|bash script|linux|macos)\b/i.test(t)) return "other";
  if (/\b(?:win32|win64|pe32|peexe|pedll|dll|exe|executable|windows|msi|installer|lnk|shortcut|vbs|vbscript|vba|powershell|ps1|bat|batch|cmd|hta|jscript|javascript|html|ms word|ms excel|ms powerpoint|office|word|excel|rtf|doc|docx|xls|xlsm|ocx|sys|scr)\b/i.test(t)) return "windows";
  return "unknown";
}

/** TweetFeed tags such as "#apk #mirai": true when the post is about a non-Windows file. */
export const taggedNonWindows = (tags = "") => /#?(?:android|apk|linux|elf|mirai|gafgyt|macos|osx|ios|ipa|mach-?o)\b/i.test(String(Array.isArray(tags) ? tags.join(" ") : tags));

// ---------- headlines and feature titles ----------

/**
 * A headline or feature title that is about another operating system and not Windows:
 * "Recovery Lock management for macOS", "New Linux antivirus settings", "GhostMap: The Android flaw ...".
 * A title that also names Windows ("custom compliance scripts on Windows and macOS") stays.
 */
export function nonWindowsTitle(title = "") {
  const t = String(title);
  return /\b(?:android|ios|ipados|iphone|ipad|macos|os x|linux|ubuntu|unix|aosp)\b|\bios\//i.test(t) && !/\bwindows\b|\bwin(?:32|64)\b/i.test(t);
}
