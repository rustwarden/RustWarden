# Alert rules

**Alerts > Rules**

Alert rules decide what happens to an alert **after** it's raised. Use them to quieten noisy alerts at night, make sure you never miss one particular program, or stop an alert from repeating every few seconds.

!!! note
    Rules never stop an alert from being **recorded** in the alert log. They only change how it's delivered.

## Conditions

A rule has conditions, and **all** of them must match:

| Condition | Example |
|---|---|
| **Alert type** | *First network activity*, or **Any alert** |
| **App** | Picked from a list with icons, or **Any app** |
| **Text contains** | Words in the alert's text or target, such as an IP or a domain |
| **Only between** | A time window, which may run past midnight, such as `22:00` to `07:00` |
| **Days** | The days of the week the rule applies (pick at least one) |

## Actions

| Action | Effect |
|---|---|
| **Mute** | The alert is still logged, but there's no popup, no event log entry and no notification, and it arrives already read. |
| **Escalate** | The alert becomes **Important** and shows a popup. |
| **Keep on this PC** | The alert isn't sent to notification plugins. |
| **Limit repeats** | Notify at most once every **N minutes** for the same alert type and app. |

## Order

Rules are checked from the top of the list down, and the **first enabled rule that matches** applies. Put specific rules above general ones. Each rule has its own switch, and **Remove** deletes it. You can have up to 64 rules.

## Examples

- **Quiet nights:** Any alert, any app, between 23:00 and 07:00, every day → **Mute**.
- **Never miss remote access:** *RDP detection* → **Escalate**.
- **Stop a chatty updater:** *First network activity*, app `updater.exe` → **Limit repeats**, 60 minutes.
- **Private alerts stay private:** *Microphone and camera access* → **Keep on this PC**.

The test button in **Settings > Other > General** follows your rules too, including in Demo mode, so you can check a rule before relying on it.
