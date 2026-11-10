# Notifications

RustWarden can send alerts to your phone or chat app through the **Notification Plugins** in **Settings > Plugins**.

| Service | What you enter |
|---|---|
| **Discord** | A channel webhook URL (*Channel settings > Integrations > Webhooks*) |
| **Slack / Mattermost / Rocket.Chat** | An incoming webhook URL |
| **Pushbullet** | An access token |
| **ntfy** | The topic URL, for example `https://ntfy.sh/my-topic` |
| **Gotify** | The server URL and an application token |
| **Generic webhook** | Any URL. RustWarden posts JSON with `level`, `title` and `text`. |

Webhook URLs and tokens are stored **encrypted** with Windows DPAPI. Red (Important) alerts are sent in red, and the rest in green, where the service supports colours.

## Setting one up

1. Switch the service on in **Settings > Plugins > Notification Plugins**.
2. Open its **Settings**, fill in the address or token, and press **Send test alert**.
3. **Save**.

## Choosing which alerts are sent

An alert is sent to **every** notification plugin that's switched on, **for each alert type that has "Send to Notification Plugins" ticked** in **Settings > Alerts > Alert types**. That option is greyed out until at least one notification plugin is on.

You can refine this further with [alert rules](../alerts/alert-rules.md):

- **Keep on this PC** stops matching alerts from being sent.
- **Mute** stops the popup and the notification.
- **Limit repeats** sends at most one per N minutes.

## Snooze

**Snooze alerts** (tray menu, or **Snooze 1 h** on the Alerts tab) pauses notifications for an hour. To keep sending to these services even while snoozed, switch on **Keep sending to these services while alerts are snoozed**.

## When the internet is down

Alerts raised while the internet is down are held (up to 50) and sent once it's back, with "(Delayed …)" added to the text.

## Weekly summary

**Send a weekly summary to these services**, then pick a weekday and hour. RustWarden sends the [weekly report](../alerts/index.md#weekly-report) to your notification services. The first one goes out at the next slot after you switch it on, and nothing is sent unless a service is set up. Demo mode sends nothing.

## Windows event log

Separately from plugins, alerts can be written to the **Windows event log** (Application log, source "RustWarden"). Switch it on in **Settings > Alerts > Options**, and per alert type in **Alert types**.
