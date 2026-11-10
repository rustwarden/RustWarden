# Rescue: removing every RustWarden rule

If a block goes wrong, there are three ways to undo **everything** RustWarden has done to your firewall. Each one removes only RustWarden's own rules. Rules made by Windows, other firewall apps or by hand are never touched.

## 1. Restore firewall defaults (in the app)

- **RustWarden menu > Restore firewall defaults**, or
- **Settings > Firewall > Advanced > Restore firewall defaults > Restore…**

This deletes every Windows Firewall rule in the **"RustWarden"** group, and also clears:

- per-program allow and block rules, and the ICMP rules from Prompt
- destination rules and Block by domain rules and lists
- blocks from Live Connections and Malicious IP protection
- bandwidth limits and priority QoS policies
- VPN kill switch, DNS-over-HTTPS and peer-to-peer guard rules

## 2. Disable the firewall (temporary)

**Firewall tab > Mode > Disabled**, or **tray menu > Firewall > Disable**. RustWarden's block rules are switched **off** but kept, so every program can use the network again. Turn it back on to restore them.

## 3. The rescue command (when the app won't open)

```
RustWarden.exe --remove-all-rules
```

Run it from a terminal opened **as administrator**. It removes every Windows Firewall rule and QoS policy RustWarden owns, undoes Block All, and exits without opening a window.

- Rules RustWarden **imported** from another firewall app are handed back to that app, not deleted.
- Each removal is written to `%LOCALAPPDATA%\RustWarden\rescue.log`. If you started it from a terminal, the output also shows there.

| Exit code | Meaning |
|---|---|
| `0` | Done |
| `1` | Some rules couldn't be removed (see the log) |
| `2` | Not run as administrator. Nothing was changed. |

### Running it with no working desktop

Because it opens no window, it can run as SYSTEM from a scheduled task. In a terminal opened as administrator:

```
schtasks /create /tn "RustWarden rescue" /sc once /st 00:00 /rl highest /ru SYSTEM /tr "\"C:\Program Files\RustWarden\RustWarden.exe\" --remove-all-rules"
schtasks /run /tn "RustWarden rescue"
```

Change the path to wherever `RustWarden.exe` is. You can delete the task afterwards with `schtasks /delete /tn "RustWarden rescue" /f`.

## Other command-line options

| Option | What it does |
|---|---|
| `--remove-all-rules` | The rescue command above |
| `--verify-alert-log` | Checks that the [alert log](../alerts/index.md#tamper-evident-log) hasn't been edited, and reports the first entry that was |
| `--install-service` / `--uninstall-service` | Installs or removes the [Windows service](../getting-started/install.md#run-as-administrator-without-a-prompt-every-time) (needs administrator rights) |
