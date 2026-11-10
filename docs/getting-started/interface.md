# The window

## Layout

The main window has a header, a row of main tabs, sometimes a row of sub-tabs, and the page itself.

| Main tab | Sub-tabs | Guide |
|---|---|---|
| **Traffic** | Graph, Usage, Map (view switch) | [Traffic](../traffic.md) |
| **Firewall** | Firewall, Live Connections, Destination Rules, Limits / QoS | [Firewall](../firewall/index.md) |
| **Alerts** | Alerts, Rules | [Alerts](../alerts/index.md) |
| **Network** | Network Scanner, the tabs plugins add (Ping Monitor, Speedtest, Port Forwarding, Cloudflare Tunnel, Shodan, AbuseIPDB…), DNS Log | [Network](../network/scanner.md) |
| **Hardware** | — | [Hardware](../hardware.md) |

RustWarden reopens on the tab and sub-tab you were last on, with the same Traffic view, time range, window size and position.

You can resize the window by dragging any point on its edge. Table columns on the Firewall, Live Connections, DNS Log, Destination Rules and Network Scanner tabs can be resized by dragging the borders in their headers.

## The RustWarden menu

Click the **RustWarden** logo at the top left to open the app menu:

| Item | What it does |
|---|---|
| Restart as administrator | *(Live mode, when not elevated)* Restarts with administrator rights. |
| Restore firewall defaults | *(Live mode)* Removes every rule RustWarden created. See [Rescue](../firewall/rescue.md). |
| Destination rules… | Opens Firewall > Destination Rules. |
| Limits / QoS… | Opens Firewall > Limits / QoS. |
| Settings… | Opens Settings. |
| Block an app by clicking it | Pick a window on screen to block its program. See [Block by clicking](../firewall/index.md#block-an-app-by-clicking-it). |
| Save snapshot | Saves a PNG picture of the current view. |
| Check for updates | Looks for a new release now. See [Updates](../maintenance.md#updates). |
| Restart service | Restarts RustWarden. |
| About RustWarden | Version, credits, and a picture of the project's own knowledge graph. |

## The tray icon

Closing the window hides RustWarden in the system tray, where it keeps running. The tray icon shows a badge when there are unread alerts. Right-click it for:

- **Show/Hide RustWarden**
- **Theme**: System, Light or Dark
- **Alerts**: opens the Alerts tab
- **Settings…**
- **Block an app by clicking it**
- **Snooze alerts**: pauses alert popups and notifications for one hour (click again to end it early)
- **Firewall**: choose Manual Blocking, Prompt or Block All, or **Disable** the firewall
- **Prompt for**: how long Prompt mode stays on (Always, 10 or 30 minutes, 1 or 2 hours)
- **Restart service**
- **Exit**

If [tamper protection](../maintenance.md#tamper-protection) is on, Settings, Exit and Restart ask for the password.

## Popups

RustWarden's desktop popups look like Windows 11 notifications. They slide in next to the taskbar, wherever it is, and **never take focus** from what you are doing. They stack in one corner: threats nearest the corner, then Prompt questions, then alerts.

- **Prompt popups** ask about a program that is trying to connect. See [Prompt](../firewall/index.md#prompt).
- **Malicious IP popups** have a red edge and a red **Block** button. See [Malicious IP protection](../protection/malicious-ip.md).
- **Alert popups** show one alert. Click one to jump to what it is about. Its gear icon opens that alert's settings.

**Settings > Personalise > Popups** sets the corner, how long alert popups stay up, and how many show at once. Prompt popups stay until you answer them.

## Look and feel

**Settings > Personalise > Theme**:

- **Follow the Windows theme** (on by default) switches between light and dark when Windows does. Turn it off to choose one yourself.
- **Use Windows accent colour** follows the Windows accent colour live and also colours the traffic graph. Turn it off to pick from the Windows colour grid or a custom colour.
- **Acrylic intensity** sets how much of what is behind the window shows through. **Tint with wallpaper colour** uses Mica instead of grey acrylic.
- **UI scale**, from 1.0× to 1.5×, scales every window, popup and banner.
- **Popup opacity** sets the least opaque the Traffic detail popups get. Notifications are always solid.

**Settings > General > General > Show rates in bits** shows speeds in bits (Mbps) instead of bytes (MB/s).

## Settings

Settings opens as a window with a sidebar of pages. Most changes apply when you press **Save**, and **Cancel** throws them away. A few switches apply straight away and say so. The [Settings reference](../settings.md) lists every page.
