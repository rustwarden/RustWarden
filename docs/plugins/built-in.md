# Built-in plugins

Each of these is part of `RustWarden.exe`. Switch it on in **Settings > Plugins** and press **Settings** on its row to configure it. Settings from earlier RustWarden versions are carried over automatically.

## Home Assistant

Matches the devices the [network scanner](../network/scanner.md) finds to your Home Assistant devices, by **MAC address**. Matched devices show their HA **name**, **area** and a coloured **device-type icon** (light, plug, sensor and so on), with a link to the device's page in Home Assistant. [Scanner alerts](../alerts/alert-types.md#your-local-network-network-scanner) include the HA name and area too.

**Settings:**

- **Address**: for example `http://homeassistant.local:8123`.
- **Long-lived access token**: create one in Home Assistant under *your profile > Security*. It's stored encrypted.
- **Test connection** checks the address and token.
- **Prefer HA entity name** shows the Home Assistant name instead of the network name on the Scanner tab.
- **Show device type** shows the type icon beside matched devices.
- **Sync now** looks every scanned device up again.

Your Home Assistant host is never blocked by [Malicious IP protection](../protection/malicious-ip.md#never-blocked).

## Ping Monitor

Pings hosts you choose every 30 seconds and charts their latency and loss. See [Ping Monitor](../network/ping-speedtest.md#ping-monitor).

## Speedtest

Download, upload, ping and jitter tests with Ookla's `speedtest-cli`. See [Speedtest](../network/ping-speedtest.md#speedtest).

## VirusTotal

Hash lookups for every program that uses the network. See [VirusTotal](../protection/virustotal.md).

## Prometheus Metrics

Serves metrics for Prometheus, Grafana and similar tools.

- Scrape `http://127.0.0.1:9877/metrics`. The **Port** is set in the plugin's settings.
- It listens on **this computer only** (127.0.0.1), and only while the plugin is switched on. Requests whose `Host` isn't localhost are refused.
- It reports 24-hour internet traffic, blocked connections, alerts by kind and the ten busiest apps.
- It makes no outbound connections.

Demo mode serves sample numbers.

## UPnP Port Forwarding

**Network > Port Forwarding.** For when you can't reach the router's own settings: RustWarden asks the router, over UPnP, to open a random **public** port that leads to a port on this PC.

1. Press **Find my router**.
2. Type the **port on this PC** (say `80`), choose the protocol and add a description.
3. Press **Forward**. The tab shows the **public address and port**, with a **Copy address** button.

- Mappings are named **"RustWarden: \<description\>"** on the router and listed under **Forwarded ports**. You can remove them one by one or with **Remove all**.
- The plugin warns when the router's public address isn't really public (a shared provider address, also called CGNAT), because then a forward wouldn't work from the internet.
- If the router doesn't report its public address, copy it from the router's status page. With a VPN on, a website would show the VPN's address instead.

Demo mode works against a made-up router.

## Cloudflare Tunnel

**Network > Cloudflare Tunnel.** Makes a service on this PC reachable from the internet through Cloudflare, without opening any ports.

The page credits cloudflared to Cloudflare, Inc. (Apache License 2.0). See [Third-party data and credits](../credits.md).

- **Download cloudflared** fetches Cloudflare's `cloudflared` (about 55 MB, a pinned version) from GitHub. It's only kept if its SHA-256 matches.
- **Sign in** in one of two ways:
    - **Tunnel token**: paste a token from the Cloudflare dashboard, or
    - **Log in with Cloudflare**: cloudflared opens your browser. Choose the domain the tunnel may use, then fill in the **tunnel name**, the **public hostname** (a DNS record is added for it) and where to **send traffic to**.
- **Start tunnel** runs the tunnel while RustWarden runs. It stops when RustWarden closes.

!!! warning
    The "Log in with Cloudflare" path hasn't been tried against a real Cloudflare account yet.

Demo mode pretends to run a tunnel.

## Shodan InternetDB

**Network > Shodan.** Look up an address, or press **Check my public address**, to see what the internet sees: **open ports**, **known vulnerabilities** (CVEs) and **host names**, from Shodan's free InternetDB. No key is needed. Only the address you ask about is sent (and, for your own address, a request to `api.ipify.org` to find it).

## AbuseIPDB

**Network > AbuseIPDB.** Look up how often an address has been **reported for abuse**.

- Needs a free API key (**Get a free API key**: 1,000 lookups a day). It's stored encrypted.
- With the **Read your alerts** permission and **Check the addresses in alerts automatically** on, the public addresses in alerts are scored once a day. RustWarden notifies you when a score reaches your **Notify from a score of** level.
- **Recent lookups** are listed on the tab.

## Notification plugins

Discord, Slack / Mattermost / Rocket.Chat, Pushbullet, ntfy, Gotify and a generic webhook. See [Notifications](notifications.md).
