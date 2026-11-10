# Behaviour baseline

The behaviour baseline learns what is **normal** for each program, and alerts you when a program steps outside it. It catches the things a rule can't: a program that suddenly talks to a new country, uploads ten times its usual amount, or wakes up at 3 a.m.

## Turning it on

**Settings > Alerts > Options > Behaviour baseline** (off by default, needs administrator rights).

| Setting | Meaning |
|---|---|
| **Baseline window** | Built from the last **N days** of stored traffic (14 by default), with **no alerts for the first M days** (7 by default) while it learns |
| **Repeat the same alert at most every** | Throttle, in hours |
| **Learn networks too** | Also learns each program's usual **networks** (AS numbers), not just countries. Each internet address is then sent to the net-info lookup service, and Team Cymru is chosen if none is set. |

## What it learns

For each program:

- its usual **countries** (and networks, if switched on),
- its usual **active hours**,
- its usual **daily volume**.

## The alerts

| Alert | Raised when |
|---|---|
| [Behaviour: new country or network](../alerts/alert-types.md#behaviour-new-country-or-network) | The program contacts a country or network outside its usual set |
| [Behaviour: traffic spike](../alerts/alert-types.md#behaviour-traffic-spike) | It moves far more data in a day than usual |
| [Behaviour: unusual hour](../alerts/alert-types.md#behaviour-unusual-hour) | It's busy at an hour when it's almost never active |

Each alert says **why**, for example *"contacted a country it never used before. Usual: US, NL."* These alerts show as **purple pins** on the [Traffic graph](../traffic.md#alert-pins).

## Teaching it

When an alert is expected, press **Mark as normal** on the graph pin or on the alert's card in the Alerts log. The baseline learns from it, and repeats are throttled.
