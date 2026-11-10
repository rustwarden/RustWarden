# Limits / QoS

**Firewall > Limits / QoS**, also in the RustWarden menu.

Cap how fast a program can use the network, for example *Dropbox may upload at 2 Mbps at most*, or give programs a priority.

## Setting a limit

1. Pick the **program**.
2. Type a **rate** in Kbps or Mbps.
3. Press **Set limit**.

Setting a limit on a program that already has one changes it. The switch on each row turns a limit off without losing it. Critical Windows programs can't be limited. Limits need administrator rights.

## Normal mode: upload limits through Windows QoS

In Normal mode, Windows enforces the limit with a **QoS policy** (`New-NetQosPolicy`). Nothing runs in the background and no driver is involved.

- Policies are named `RustWarden QoS <id> <program>`.
- They are re-checked every minute, so a policy removed by hand comes back.
- **Restore firewall defaults** and `RustWarden.exe --remove-all-rules` remove them all.

!!! note
    Windows has no user-mode way to cap **downloads**, so in Normal mode only **uploads** are limited. Driver mode can also limit downloads.

## Driver mode: downloads, both directions, and pacing

With [Driver mode](../driver-mode.md) on and the driver installed, a **Direction** dropdown appears: **Upload**, **Download** or **Upload & Download**, each with its own rate. The WinDivert driver enforces the cap:

- It works **over a VPN**.
- It's paced **per program**, across all of that program's connections.
- Only the limited program's own connections go through the driver. Everything else, including a VPN's tunnel, is left alone.
- A new connection is picked up within about a tenth of a second, so a very short burst at the start of a fast download can get through before the cap takes hold.
- A connection that was already open when the engine started is found for TCP. An open UDP/QUIC stream is limited once it reconnects.

**Safety cut-out.** If Windows Firewall starts dropping the packets the driver sends on (for example with a strict default-deny firewall), the engine switches itself off within seconds and the limit says why, instead of cutting your connection. Its start, stop and a counter line every 30 seconds are written to `engine.log` in the data folder.

**Fallback.** If the driver isn't ready, uploads fall back to the QoS policy and downloads say why they aren't limited. Switching back to Normal mode returns everything to QoS.

## Priority

The **Priority** dropdown (High / Normal / Low) gives a program a priority. High and Low programs can leave both rates empty (or 0).

- **Normal and Driver mode:** Windows marks the program's uploads with a **DSCP tag** (High = EF, Low = CS1) through a RustWarden QoS policy. This helps if your router or Wi-Fi honours DSCP.
- **Driver mode:** enter your line speed in **Settings > Other > Advanced > Line speed** (Mbps up and down), and the programs listed in Limits / QoS **share** it:
    - **High** is never held back and goes first.
    - **Normal** gets what High leaves.
    - **Low** gets what both leave, but never less than 10% / 5% of the line.

    Programs that aren't listed aren't touched, so they don't take part in the sharing.

## Network-condition simulator (Driver mode)

The limit form also has **Add delay (ms)** and **Packet loss (%)**. They apply to every connection of that program in both directions, with or without a rate cap (leave the rate empty for none). Use them to test how a program copes with a bad connection.

- Up to **5000 ms** delay and **90%** loss.
- The simulation switches itself off after **30 minutes** (checked every minute). A limit that was only a simulation is switched off with it.
- Rows show the added delay and loss next to the rate.

## Quota caps

A [data quota](../protection/quotas.md) can cap a program's upload rate when it hits its warning level or its limit. These caps appear here like any other limit. They are lifted when the quota period resets, and are skipped if you had already limited that program yourself.

## Demo mode

Demo mode shows sample limits, and setting one changes nothing on the system.
