//! UPnP port forwarding: asks the router (over UPnP) to open a random public port that leads to a port on
//! this PC, for when the router's own settings can't be reached. RustWarden finds the router (the `upnp`
//! permission); this plugin talks to it over plain http on the local network.
//!
//! The mappings are kept in the plugin's settings so they can be listed and removed again; each is named
//! "RustWarden: <what you typed>" on the router.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, TabDef, UiTree};
use std::hash::{BuildHasher, Hasher};

struct Upnp;

const PROTOS: [&str; 2] = ["TCP", "UDP"];
/// Router errors worth knowing: the port is taken, and the router only allows leases that end.
const CONFLICT: &str = "718";
const ONLY_LEASES: &str = "725";
/// A week, for routers that refuse a permanent mapping.
const LEASE: &str = "604800";

// ---- text helpers (pure, tested below) ----

/// The text between the first `<name>` and `</name>`.
fn tag(xml: &str, name: &str) -> Option<String> {
    let start = xml.find(&format!("<{name}>"))? + name.len() + 2;
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(xml[start..end].trim().to_owned())
}

/// The router's internet service: its type and the full address to send commands to. `base` is the description's
/// address, which a relative control address is added to.
fn control_of(desc: &str, base: &str) -> Option<(String, String)> {
    let origin = base.strip_prefix("http://").map(|r| format!("http://{}", r.split('/').next().unwrap_or("")))?;
    desc.split("<service>").skip(1).find_map(|block| {
        let kind = tag(block, "serviceType")?;
        if !(kind.contains(":WANIPConnection:") || kind.contains(":WANPPPConnection:")) {
            return None;
        }
        let url = tag(block, "controlURL")?;
        let full = if url.starts_with("http://") { url } else { format!("{origin}/{}", url.trim_start_matches('/')) };
        Some((kind, full))
    })
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A SOAP request body calling `action` of `service`.
fn envelope(service: &str, action: &str, args: &[(&str, &str)]) -> String {
    let args: String = args.iter().map(|(k, v)| format!("<{k}>{}</{k}>", escape(v))).collect();
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{service}\">{args}</u:{action}></s:Body></s:Envelope>"
    )
}

/// What the router said: the answer's body, or the router's own error code (`718`) and text.
fn soap(control: &str, service: &str, action: &str, args: &[(&str, &str)]) -> Result<String, String> {
    let headers = vec!["Content-Type: text/xml; charset=\"utf-8\"".to_owned(), format!("SOAPAction: \"{service}#{action}\"")];
    let (status, body) = guest::http_raw(control, &headers, Some(&envelope(service, action, args)), false)?;
    if status == 200 {
        return Ok(body);
    }
    Err(match (tag(&body, "errorCode"), tag(&body, "errorDescription")) {
        (Some(code), text) => format!("{code}: {}", text.unwrap_or_default()),
        _ => format!("the router answered HTTP {status}"),
    })
}

/// True for an address that is not reachable from the internet (a private range, or the shared 100.64.0.0/10 range
/// providers use when they share one public address between customers).
fn not_public(ip: &str) -> bool {
    let p: Vec<u32> = ip.split('.').filter_map(|x| x.parse().ok()).collect();
    matches!(p.as_slice(), [10, ..] | [192, 168, ..] | [127, ..] | [169, 254, ..] | [172, 16..=31, ..] | [100, 64..=127, ..] | [0, ..])
}

fn random_port() -> u16 {
    20_000 + (std::hash::RandomState::new().build_hasher().finish() % 40_000) as u16
}

// ---- saved state ----

#[derive(Clone, Debug, PartialEq)]
struct Map {
    internal: u16,
    external: u16,
    proto: String,
    desc: String,
}

fn load_maps() -> Vec<Map> {
    parse_maps(&guest::config_get("maps"))
}

fn parse_maps(text: &str) -> Vec<Map> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            Some(Map { internal: f.next()?.parse().ok()?, external: f.next()?.parse().ok()?, proto: f.next()?.to_owned(), desc: f.next().unwrap_or("").to_owned() })
        })
        .collect()
}

fn save_maps(maps: &[Map]) {
    let text: Vec<String> = maps.iter().map(|m| format!("{}\t{}\t{}\t{}", m.internal, m.external, m.proto, m.desc)).collect();
    guest::config_set("maps", &text.join("\n"));
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(40).collect()
}

struct Router {
    control: String,
    service: String,
    local_ip: String,
}

fn saved_router() -> Option<Router> {
    let (control, service, local_ip) = (guest::config_get("control"), guest::config_get("service"), guest::config_get("local_ip"));
    (!control.is_empty() && !service.is_empty() && !local_ip.is_empty()).then_some(Router { control, service, local_ip })
}

/// Finds the router and remembers where to send commands. Slow (about 3 seconds), so only on a button press.
fn find_router() -> Result<Router, String> {
    if guest::is_demo() {
        let r = Router { control: "http://192.168.1.1:5000/ctl/IPConn".into(), service: "urn:schemas-upnp-org:service:WANIPConnection:1".into(), local_ip: "192.168.1.20".into() };
        guest::config_set("ext_ip", "203.0.113.7");
        return Ok(save_router(r));
    }
    let gateway = guest::upnp_discover()?;
    let (status, desc) = guest::http_raw(&gateway.location, &[], None, false)?;
    if status != 200 {
        return Err(format!("the router's description answered HTTP {status}"));
    }
    let (service, control) = control_of(&desc, &gateway.location).ok_or("the router has no UPnP internet connection service")?;
    let r = save_router(Router { control, service, local_ip: gateway.local_ip });
    let ip = soap(&r.control, &r.service, "GetExternalIPAddress", &[]).ok().and_then(|b| tag(&b, "NewExternalIPAddress")).unwrap_or_default();
    guest::config_set("ext_ip", &ip);
    Ok(r)
}

fn save_router(r: Router) -> Router {
    guest::config_set("control", &r.control);
    guest::config_set("service", &r.service);
    guest::config_set("local_ip", &r.local_ip);
    r
}

fn forget_router() {
    for k in ["control", "service", "local_ip", "ext_ip"] {
        guest::config_set(k, "");
    }
}

/// Opens a random public port to `internal` on this PC.
fn forward(internal: u16, proto: &str, desc: &str) -> Result<Map, String> {
    let router = match saved_router() {
        Some(r) => r,
        None => find_router()?,
    };
    let maps = load_maps();
    let label = format!("RustWarden: {}", if desc.is_empty() { "port forward" } else { desc });
    let mut lease = "0";
    for _ in 0..8 {
        let external = random_port();
        if maps.iter().any(|m| m.external == external && m.proto == proto) {
            continue;
        }
        if guest::is_demo() {
            return Ok(Map { internal, external, proto: proto.to_owned(), desc: desc.to_owned() });
        }
        let (e, i) = (external.to_string(), internal.to_string());
        let args = [
            ("NewRemoteHost", ""),
            ("NewExternalPort", e.as_str()),
            ("NewProtocol", proto),
            ("NewInternalPort", i.as_str()),
            ("NewInternalClient", router.local_ip.as_str()),
            ("NewEnabled", "1"),
            ("NewPortMappingDescription", label.as_str()),
            ("NewLeaseDuration", lease),
        ];
        match soap(&router.control, &router.service, "AddPortMapping", &args) {
            Ok(_) => return Ok(Map { internal, external, proto: proto.to_owned(), desc: desc.to_owned() }),
            Err(e) if e.starts_with(CONFLICT) => {}
            Err(e) if e.starts_with(ONLY_LEASES) && lease == "0" => lease = LEASE,
            Err(e) => {
                // The saved router may be stale (a new router, a new address): look again next time.
                forget_router();
                return Err(e);
            }
        }
    }
    Err("the router kept refusing the ports tried".into())
}

fn unforward(m: &Map) -> Result<(), String> {
    if guest::is_demo() {
        return Ok(());
    }
    let router = saved_router().ok_or("the router isn't known yet: press Find my router")?;
    let e = m.external.to_string();
    soap(&router.control, &router.service, "DeletePortMapping", &[("NewRemoteHost", ""), ("NewExternalPort", e.as_str()), ("NewProtocol", m.proto.as_str())]).map(|_| ())
}

// ---- the page ----

fn num(key: &str, default: u16) -> u16 {
    guest::config_get(key).parse().ok().filter(|p| *p >= 1).unwrap_or(default)
}

fn page() -> UiTree {
    let ip = guest::config_get("ext_ip");
    let router = saved_router();
    let mut rows = vec![
        UiTree::Weak(
            "For when you can't reach the router's own settings: RustWarden asks the router (UPnP) to open a random public port that leads to a port on this PC. Needs UPnP switched on in the router."
                .into(),
        ),
        UiTree::Row(vec![
            UiTree::Button { id: "find".into(), text: "Find my router".into() },
            UiTree::Label(match (&router, ip.is_empty()) {
                (None, _) => "No router found yet".to_owned(),
                (Some(_), true) => "Router found; its public address is unknown".to_owned(),
                (Some(_), false) => format!("Router found. Public address: {ip}"),
            }),
        ]),
    ];
    if !ip.is_empty() && not_public(&ip) {
        rows.push(UiTree::Label("⚠ The router's address is not a public one (your provider shares one address between customers, or another router sits in front). A forwarded port will not be reachable from the internet.".into()));
    }
    let msg = guest::config_get("msg");
    if !msg.is_empty() {
        rows.push(UiTree::Label(msg));
    }
    rows.push(UiTree::Separator);
    rows.push(UiTree::Heading("Forward a port".into()));
    rows.push(UiTree::Row(vec![
        UiTree::Label("Port on this PC".into()),
        UiTree::Number { id: "internal".into(), value: f64::from(num("internal", 80)), min: 1.0, max: 65535.0 },
        UiTree::Dropdown { id: "proto".into(), options: PROTOS.iter().map(|p| (*p).to_owned()).collect(), selected: usize::from(guest::config_get("proto") == "UDP") },
        UiTree::TextField { id: "desc".into(), value: guest::config_get("desc") },
        UiTree::Button { id: "forward".into(), text: "Forward".into() },
    ]));
    rows.push(UiTree::Weak("The description names the mapping on the router, as \"RustWarden: <description>\".".into()));
    rows.push(UiTree::Separator);
    let maps = load_maps();
    rows.push(UiTree::Heading("Forwarded ports".into()));
    if maps.is_empty() {
        rows.push(UiTree::Weak("None yet.".into()));
    }
    for (i, m) in maps.iter().enumerate() {
        let shown = if ip.is_empty() { format!(":{}", m.external) } else { format!("{ip}:{}", m.external) };
        let mut row = vec![UiTree::Label(format!("{shown} → this PC, port {} ({}) {}", m.internal, m.proto, m.desc))];
        row.push(UiTree::Copy { label: "Copy address".into(), value: shown });
        row.push(UiTree::Button { id: format!("rm:{i}"), text: "Remove".into() });
        rows.push(UiTree::Row(row));
    }
    if !maps.is_empty() {
        rows.push(UiTree::Button { id: "rm_all".into(), text: "Remove all".into() });
    }
    UiTree::Column(rows)
}

fn say(msg: &str) {
    guest::config_set("msg", msg);
}

fn click(id: &str) {
    match id {
        "find" => {
            forget_router();
            say(&find_router().map_or_else(|e| format!("⚠ {e}"), |_| String::new()));
        }
        "forward" => {
            let (internal, proto) = (num("internal", 80), if guest::config_get("proto") == "UDP" { "UDP" } else { "TCP" });
            match forward(internal, proto, &clean(&guest::config_get("desc"))) {
                Ok(m) => {
                    let mut maps = load_maps();
                    maps.push(m);
                    save_maps(&maps);
                    say("");
                }
                Err(e) => say(&format!("⚠ Couldn't forward the port: {e}")),
            }
        }
        "rm_all" => {
            let (mut kept, mut failed) = (Vec::new(), String::new());
            for m in load_maps() {
                if let Err(e) = unforward(&m) {
                    failed = e;
                    kept.push(m);
                }
            }
            save_maps(&kept);
            say(&if failed.is_empty() { String::new() } else { format!("⚠ Some ports couldn't be removed: {failed}") });
        }
        _ => {
            if let Some(i) = id.strip_prefix("rm:").and_then(|i| i.parse::<usize>().ok()) {
                let mut maps = load_maps();
                if i < maps.len() {
                    match unforward(&maps[i]) {
                        Ok(()) => {
                            maps.remove(i);
                            save_maps(&maps);
                            say("");
                        }
                        Err(e) => say(&format!("⚠ Couldn't remove it: {e}")),
                    }
                }
            }
        }
    }
}

impl Guest for Upnp {
    fn manifest() -> Manifest {
        Manifest {
            id: "upnp".into(),
            name: "UPnP Port Forwarding".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            tabs: vec![TabDef { id: "upnp".into(), title: "Port Forwarding".into() }],
            // The router's address on the local network isn't known in advance.
            http_hosts: vec!["*".into()],
            permissions: vec!["upnp".into()],
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderTab { .. } => Reply::Ui(page()),
            Call::Event(Event::Click { id }) => {
                click(&id);
                Reply::Done
            }
            Call::Event(Event::Number { id, value }) if id == "internal" => {
                guest::config_set("internal", &(value.round() as u32).clamp(1, 65535).to_string());
                Reply::Done
            }
            Call::Event(Event::Index { id, index }) if id == "proto" => {
                guest::config_set("proto", PROTOS[index.min(1)]);
                Reply::Done
            }
            Call::Event(Event::Text { id, value }) if id == "desc" => {
                guest::config_set("desc", &clean(&value));
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Upnp);

#[cfg(test)]
mod tests {
    use super::*;

    const DESC: &str = "<root><device><deviceList><device><deviceList><device><serviceList>\
        <service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/ctl/CmnIfCfg</controlURL></service>\
        <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service>\
        </serviceList></device></deviceList></device></deviceList></device></root>";

    #[test]
    fn finds_the_internet_service_and_makes_its_address_absolute() {
        let (kind, url) = control_of(DESC, "http://192.168.1.1:5000/rootDesc.xml").unwrap();
        assert_eq!(kind, "urn:schemas-upnp-org:service:WANIPConnection:1");
        assert_eq!(url, "http://192.168.1.1:5000/ctl/IPConn");
        assert!(control_of("<root></root>", "http://192.168.1.1/d.xml").is_none());
    }

    #[test]
    fn the_request_escapes_what_you_typed() {
        let body = envelope("urn:x:service:WANIPConnection:1", "AddPortMapping", &[("NewPortMappingDescription", "a<b>&\"c")]);
        assert!(body.contains("<NewPortMappingDescription>a&lt;b&gt;&amp;&quot;c</NewPortMappingDescription>"));
        assert!(body.contains("<u:AddPortMapping xmlns:u=\"urn:x:service:WANIPConnection:1\">"));
    }

    #[test]
    fn reads_a_router_error() {
        let body = "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode><errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        assert_eq!(tag(body, "errorCode").as_deref(), Some("718"));
        assert_eq!(tag(body, "errorDescription").as_deref(), Some("ConflictInMappingEntry"));
    }

    #[test]
    fn spots_addresses_the_internet_cannot_reach() {
        for ip in ["10.1.2.3", "192.168.0.9", "172.20.1.1", "100.64.0.1", "100.127.255.1"] {
            assert!(not_public(ip), "{ip}");
        }
        for ip in ["203.0.113.7", "8.8.8.8", "172.32.0.1", "100.128.0.1"] {
            assert!(!not_public(ip), "{ip}");
        }
    }

    #[test]
    fn mappings_survive_saving() {
        let text = "80\t41234\tTCP\tweb\n22\t50000\tUDP\t";
        let maps = parse_maps(text);
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[0], Map { internal: 80, external: 41234, proto: "TCP".into(), desc: "web".into() });
        assert_eq!(maps[1].desc, "");
    }
}
