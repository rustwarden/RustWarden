# Data plan and quotas

Two ways to keep data use in check:

- a **data plan**: one allowance for the whole PC, which warns you;
- **quotas**: limits per program, or for all traffic, which can warn, slow the program down or block it.

## Data plan

**Settings > Data Plan**

| Setting | Meaning |
|---|---|
| **Warn at 75% and when over the limit** | Turns the plan on, along with the [Data plan](../alerts/alert-types.md#data-plan) alert |
| **Allowance** | What's counted (download, upload or both), the period (day, week or month) and the size in GB |
| **Don't count local network traffic** | Only internet traffic counts |

## Quotas

**Settings > Quotas**

Press **Add quota**, then set:

| Setting | Meaning |
|---|---|
| **Applies to** | **All traffic**, or one program (picked from a list with icons) |
| **Limit** | Day, week or month, and an amount in MB or GB |
| **Warn and act** | What happens at 100%, and the warning percentage (80% by default) |
| **Upload cap** | *(Only for the "Limit upload" actions)* The upload rate cap, in Kbps |

Each quota has its own on/off switch and a **Remove** button, and shows a live progress bar.

### Actions at 100%

| Action | What happens |
|---|---|
| **Nothing at 100%** | Only the warning alert, and the progress bar |
| **Alert at 100%** | Alerts at the warning level and at 100% |
| **Block at 100%** | Alerts, then **blocks the program** through the firewall at 100%. Needs administrator rights. |
| **Limit upload at 100%** | Alerts, then caps the program's upload rate at 100% |
| **Limit upload at warning, block at 100%** | Slows the program from the warning level, and blocks it only at the limit |

The block and limit actions need a single program, so they aren't offered for "All traffic".

### How counting works

- **Local network traffic isn't counted.**
- Counters come from the stored traffic history, so they **survive restarts** and follow the calendar when a period rolls over or the clock changes.
- Alerts go through the usual [alert settings](../alerts/index.md#setting-up-alerts): Alerts tab, tray badge, event log and notification plugins.

### Lifting blocks and caps

- A quota block is **lifted automatically** when the period resets, or when you raise or remove the quota.
- An upload cap is a normal [bandwidth limit](../firewall/limits-qos.md). It shows on the Limits / QoS tab and is lifted when the period resets or the quota changes. It's skipped if you'd already limited that program yourself.
- A block you set **yourself** is never touched by a quota.

### Where you see it

- The progress bar on the Quotas page.
- A **Quota** bar in the program's [info popup](../firewall/index.md#the-app-info-popup).
- Quota events in the [weekly report](../alerts/index.md#weekly-report).

Demo mode shows sample quotas.
