# VirusTotal

[VirusTotal](https://www.virustotal.com) checks files against about 70 antivirus engines. RustWarden can look up every program that uses the network and show its score on the Firewall tab and in Prompt popups.

## Setting it up

1. Go to **Settings > Plugins**, switch on **VirusTotal** and open its **Settings**.
2. Press **Get a free API key**, sign up, and paste the key in. It's stored encrypted with DPAPI.
3. Optionally switch on **Scan new programs automatically**.

The free key allows **4 lookups a minute**, so a long program list takes a while the first time.

## What is sent

Only the file's **SHA-256 hash** is sent, never the file itself (unless you upload it, see below).

Each program is checked **once per file hash**. A result, including "Not found", is kept and not looked up again at startup or on a timer. A new version of a program has a new hash, so it's checked once more.

## Reading the score

The **VirusTotal** column on the Firewall tab shows:

| Shows | Meaning |
|---|---|
| `0/72` (green) | No engine flagged it |
| `3/72` (red) | 3 engines flagged it. Click it to open the VirusTotal report and judge for yourself. |
| Not scanned | No lookup yet. Use **Scan** in the row's right-click menu or the info popup. |
| Scanning… / Analysing… | A lookup or upload is in progress |
| Not found | VirusTotal has never seen this file |
| On Hold | Waiting because of the free key's rate limit |
| Skipped (over 650MB) | Too big for VirusTotal |
| Failed | The lookup failed. Try **Rescan**. |

Prompt popups and connection banners show the score in a small bubble too.

## Uploading a file

A program VirusTotal has never seen stays "Not found". To have it analysed:

1. Right-click the row, or use the **▾** menu next to **VirusTotal** in its info popup.
2. Choose **Upload to VirusTotal…**.
3. A dialog explains that the file's **contents** are shared with security vendors and may become visible to others. Only that one file is uploaded, and only once you confirm.

RustWarden **never uploads on its own**, even with automatic scanning on. Uploaded files are polled until the report arrives. Files over 650 MB are skipped, because VirusTotal doesn't accept anything larger. Each upload is written to `%LOCALAPPDATA%\RustWarden\rustwarden.log`.

## Demo mode

VirusTotal works in Live mode only. Demo mode has no file hashes or API key to look up.
