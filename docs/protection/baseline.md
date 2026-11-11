# Behaviour baseline

The behaviour baseline learns what is **normal** for each program, and alerts you when a program steps outside it. It catches the things a rule can't: a program that suddenly talks to a new country, uploads ten times its usual amount, or wakes up at 3 a.m.

## Turning it on

**Settings > Alerts > Options > Behaviour baseline** (off by default, needs administrator rights).

| Setting | Meaning |
|---|---|
| **Baseline window** | Built from the last **N days** of stored traffic (14 by default), with **no alerts for the first M days** (7 by default) while it learns |
| **Repeat the same alert at most every** | Throttle, in hours |
| **Learn domains too** | Also learns each program's usual **domains**, from the names it looked up (`a.cdn.github.com` counts as `github.com`). On by default; nothing is sent anywhere. |
| **Learn networks too** | Also learns each program's usual **networks** (AS numbers), not just countries. Each internet address is then sent to the net-info lookup service, and Team Cymru is chosen if none is set. |

## What it learns

For each program:

- its usual **countries**, **domains** and, if switched on, **networks**,
- its usual **active hours**,
- its usual **daily volume**.

## While it learns

A program's first days (7 by default) are its learning period. They count from when RustWarden first saw the program or when you switched the baseline on, whichever is later, so switching it on doesn't raise an alert for everything your long-installed programs have ever done. Switching it off and on again starts a new learning period. RustWarden still watches it: anything that would raise a behaviour alert is **logged quietly** in the Alerts log, marked *(logged while learning)*, but there's no desktop popup, no unread badge and nothing goes to notification plugins. What it saw counts as usual afterwards, so the end of the learning period doesn't bring a burst of alerts.

The traffic spike and unusual hour checks start once a program has two days of history.

## The alerts

| Alert | Raised when |
|---|---|
| [Behaviour: new country, network or domain](../alerts/alert-types.md#behaviour-new-country-network-or-domain) | The program contacts a country, network or domain outside its usual set |
| [Behaviour: traffic spike](../alerts/alert-types.md#behaviour-traffic-spike) | It moves far more data in a day than usual |
| [Behaviour: unusual hour](../alerts/alert-types.md#behaviour-unusual-hour) | It's busy at an hour when it's almost never active |

Each alert says **why**, for example *"contacted a country it never used before. Usual: US, NL."* These alerts show as **purple pins** on the [Traffic graph](../traffic.md#alert-pins).

## Teaching it

When an alert is expected, press **Mark as normal** on the graph pin or on the alert's card in the Alerts log. The baseline learns from it, and repeats are throttled.
