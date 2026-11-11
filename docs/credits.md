# Third-party data and credits

Some of what RustWarden downloads is made by other people. Wherever one of these can be downloaded, RustWarden shows a small **Source** line naming who makes it and its licence, with links. Nothing is downloaded until you switch the feature on or press its button.

## Databases

| What | Where you download it | Made by | Licence |
|---|---|---|---|
| Country, city and ASN databases | Settings > Countries & Network > Downloads, the first-run wizard, and the [Destination Rules](firewall/destination-rules.md) window | [IP Geolocation by DB-IP](https://db-ip.com) | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |

## Blocklists

The malicious IP and domain lists (Settings > Malicious IPs, see [Malicious IPs and domains](protection/malicious-ip.md)) and a list imported into [Block by domain](firewall/destination-rules.md#block-by-domain-driver-mode) each show **Lists from:** with the publisher of every list in use. Each list belongs to its publisher and is used under their terms.

| Default list | Made by |
|---|---|
| [Feodo Tracker](https://feodotracker.abuse.ch) (botnet servers) | abuse.ch |
| [IPsum](https://github.com/stamparm/ipsum) (malicious IPs) | Miroslav Štampar |
| [URLhaus Malicious Hosts Blocklist](https://gitlab.com/malware-filter/urlhaus-filter) (malicious domains) | malware-filter, from abuse.ch URLhaus data |

A list you add yourself is credited to the site it comes from.

## Programs and drivers

| What | Where you download it | Made by | Licence |
|---|---|---|---|
| WinDivert packet driver | Settings > Other > Driver (see [Driver mode](driver-mode.md)) | [basil00](https://reqrypt.org/windivert.html) | LGPL-3.0 or GPL-2.0 |
| speedtest-cli | Network > Speedtest (see [Speedtest](network/ping-speedtest.md#speedtest)) | [Speedtest® by Ookla®](https://www.speedtest.net/apps/cli), Ookla, LLC | [Ookla's End User License Agreement](https://www.speedtest.net/about/eula) |
| cloudflared | Network > Cloudflare Tunnel (see [Cloudflare Tunnel](plugins/built-in.md#cloudflare-tunnel)) | [Cloudflare, Inc.](https://github.com/cloudflare/cloudflared) | Apache License 2.0 |

Speedtest results are also shown with Ookla's credit.

## Data from your own accounts

| What | Made by |
|---|---|
| ThinkBroadband Quality Monitor graphs | [thinkbroadband.com](https://www.thinkbroadband.com/broadband/monitoring/quality), downloaded from your own account |
