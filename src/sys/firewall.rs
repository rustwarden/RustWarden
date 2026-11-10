//! Windows Firewall through `INetFwPolicy2`. This layer is mechanism only; which rules may be
//! created or deleted is decided in `live::firewall`, which only ever passes names and groups
//! that belong to RustWarden.

use windows::Win32::Foundation::{VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_PROFILE_TYPE2, NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NetFwPolicy2,
    NetFwRule,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, IDispatch};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfig2W, SC_MANAGER_CONNECT, SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_QUERY_CONFIG, SERVICE_SID_INFO, SERVICE_SID_TYPE_NONE,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface, PCWSTR};

use super::wide;

pub const PROFILE_DOMAIN: i32 = 1;
pub const PROFILE_PRIVATE: i32 = 2;
pub const PROFILE_PUBLIC: i32 = 4;
pub const PROFILES: [i32; 3] = [PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC];

/// IP protocol number meaning "any" in the firewall API.
const PROTO_ANY: i32 = 256;

#[derive(Clone, Debug)]
pub struct Rule {
    pub name: String,
    pub grouping: String,
    pub program: String,
    /// Windows service the rule is limited to (its program is the service host); empty for the whole program.
    pub service: String,
    pub outbound: bool,
    pub block: bool,
    pub enabled: bool,
}

/// What to create. `program: None` means any program.
#[derive(Clone, Debug)]
pub struct RuleSpec {
    pub name: String,
    pub description: String,
    pub grouping: String,
    pub program: Option<String>,
    pub outbound: bool,
    pub block: bool,
    pub enabled: bool,
    /// IP protocol number (6 TCP, 17 UDP) when ports are given.
    pub protocol: Option<i32>,
    pub local_ports: Option<String>,
    pub remote_ports: Option<String>,
    /// Remote address list ("1.2.3.4,5.6.7.8"); `None` means any.
    pub remote_addrs: Option<String>,
    /// Service short name the rule is limited to; needs the service's own SID (see [`service_has_sid`]).
    pub service: Option<String>,
    /// Friendly names of the network adapters the rule is limited to; `None` means all of them.
    pub interfaces: Option<Vec<String>>,
}

fn err(what: &str, e: windows::core::Error) -> String {
    // E_ACCESSDENIED: not elevated.
    if e.code().0 as u32 == 0x8007_0005 { format!("{what}: access denied (administrator rights are needed)") } else { format!("{what}: {e}") }
}

fn policy() -> Result<INetFwPolicy2, String> {
    super::com_init();
    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }.map_err(|e| err("Windows Firewall is not available", e))
}

fn rules(p: &INetFwPolicy2) -> Result<INetFwRules, String> {
    unsafe { p.Rules() }.map_err(|e| err("Can't read firewall rules", e))
}

fn read_rule(r: &INetFwRule) -> Option<Rule> {
    unsafe {
        Some(Rule {
            name: r.Name().ok()?.to_string(),
            grouping: r.Grouping().map(|b| b.to_string()).unwrap_or_default(),
            program: r.ApplicationName().map(|b| b.to_string()).unwrap_or_default(),
            service: r.ServiceName().map(|b| b.to_string()).unwrap_or_default(),
            outbound: r.Direction().ok()? == NET_FW_RULE_DIR_OUT,
            block: r.Action().ok()? == NET_FW_ACTION_BLOCK,
            enabled: r.Enabled().ok()?.as_bool(),
        })
    }
}

/// Every rule whose group equals `group`, plus how many rules exist in total. Only the group
/// string is read for the others, so enumeration stays cheap.
pub fn rules_in_group(group: &str) -> Result<(Vec<Rule>, usize), String> {
    rules_where(|rule| unsafe { rule.Grouping() }.is_ok_and(|g| g == group))
}

/// Every rule whose name starts with `prefix` (any group).
pub fn rules_named(prefix: &str) -> Result<Vec<Rule>, String> {
    rules_where(|rule| unsafe { rule.Name() }.is_ok_and(|n| n.to_string().starts_with(prefix))).map(|(r, _)| r)
}

/// Every enabled outbound allow rule (any group).
pub fn enabled_outbound_allows() -> Result<Vec<Rule>, String> {
    rules_where(|rule| unsafe { rule.Direction().is_ok_and(|d| d == NET_FW_RULE_DIR_OUT) && rule.Action().is_ok_and(|a| a == NET_FW_ACTION_ALLOW) && rule.Enabled().is_ok_and(|e| e.as_bool()) })
        .map(|(r, _)| r)
}

/// Every enabled outbound block rule (any group).
pub fn enabled_outbound_blocks() -> Result<Vec<Rule>, String> {
    rules_where(|rule| unsafe { rule.Direction().is_ok_and(|d| d == NET_FW_RULE_DIR_OUT) && rule.Action().is_ok_and(|a| a == NET_FW_ACTION_BLOCK) && rule.Enabled().is_ok_and(|e| e.as_bool()) })
        .map(|(r, _)| r)
}

/// Gives an existing rule a new group, and a new name unless it is the same.
pub fn adopt_rule(old_name: &str, new_name: &str, group: &str) -> Result<(), String> {
    let p = policy()?;
    let rule = unsafe { rules(&p)?.Item(&BSTR::from(old_name)) }.map_err(|e| err("Can't find the firewall rule", e))?;
    unsafe {
        if new_name != old_name {
            rule.SetName(&BSTR::from(new_name)).map_err(|e| err("Can't rename the firewall rule", e))?;
        }
        rule.SetGrouping(&BSTR::from(group)).map_err(|e| err("Can't regroup the firewall rule", e))
    }
}

fn rules_where(keep: impl Fn(&INetFwRule) -> bool) -> Result<(Vec<Rule>, usize), String> {
    let p = policy()?;
    let rules = rules(&p)?;
    let unknown = unsafe { rules._NewEnum() }.map_err(|e| err("Can't list firewall rules", e))?;
    let list: IEnumVARIANT = unknown.cast().map_err(|e| err("Can't list firewall rules", e))?;
    let (mut ours, mut total) = (Vec::new(), 0usize);
    loop {
        let mut item = [VARIANT::default()];
        let mut fetched = 0u32;
        let hr = unsafe { list.Next(&mut item, &mut fetched) };
        if hr.0 != 0 || fetched == 0 {
            break;
        }
        total += 1;
        let Ok(dispatch) = IDispatch::try_from(&item[0]) else { continue };
        let Ok(rule) = dispatch.cast::<INetFwRule>() else { continue };
        if keep(&rule)
            && let Some(r) = read_rule(&rule)
        {
            ours.push(r);
        }
    }
    Ok((ours, total))
}

pub fn add_rule(spec: &RuleSpec) -> Result<(), String> {
    let p = policy()?;
    let rules = rules(&p)?;
    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }.map_err(|e| err("Can't create a firewall rule", e))?;
    unsafe {
        let e = |what: &'static str| move |e| err(what, e);
        rule.SetName(&BSTR::from(spec.name.as_str())).map_err(e("set name"))?;
        rule.SetDescription(&BSTR::from(spec.description.as_str())).map_err(e("set description"))?;
        rule.SetGrouping(&BSTR::from(spec.grouping.as_str())).map_err(e("set group"))?;
        if let Some(program) = &spec.program {
            rule.SetApplicationName(&BSTR::from(program.as_str())).map_err(e("set program"))?;
        }
        rule.SetDirection(if spec.outbound { NET_FW_RULE_DIR_OUT } else { NET_FW_RULE_DIR_IN }).map_err(e("set direction"))?;
        rule.SetAction(if spec.block { NET_FW_ACTION_BLOCK } else { NET_FW_ACTION_ALLOW }).map_err(e("set action"))?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0).map_err(e("set profiles"))?;
        rule.SetProtocol(spec.protocol.unwrap_or(PROTO_ANY)).map_err(e("set protocol"))?;
        if let Some(ports) = &spec.local_ports {
            rule.SetLocalPorts(&BSTR::from(ports.as_str())).map_err(e("set local ports"))?;
        }
        if let Some(ports) = &spec.remote_ports {
            rule.SetRemotePorts(&BSTR::from(ports.as_str())).map_err(e("set remote ports"))?;
        }
        if let Some(addrs) = &spec.remote_addrs {
            rule.SetRemoteAddresses(&BSTR::from(addrs.as_str())).map_err(e("set remote addresses"))?;
        }
        if let Some(service) = &spec.service {
            rule.SetServiceName(&BSTR::from(service.as_str())).map_err(e("set service"))?;
        }
        if let Some(names) = &spec.interfaces {
            rule.SetInterfaces(&interfaces_variant(names)?).map_err(e("set adapters"))?;
        }
        rule.SetEnabled(bool_variant(spec.enabled)).map_err(e("enable"))?;
        rules.Add(&rule).map_err(|e| err("Can't add the firewall rule", e))
    }
}

/// A SAFEARRAY of BSTR variants, which is what a rule's adapter list is.
fn interfaces_variant(names: &[String]) -> Result<VARIANT, String> {
    use windows::Win32::System::Ole::{SafeArrayCreateVector, SafeArrayPutElement};
    use windows::Win32::System::Variant::{VARENUM, VT_ARRAY, VT_VARIANT};
    unsafe {
        let array = SafeArrayCreateVector(VT_VARIANT, 0, names.len() as u32);
        if array.is_null() {
            return Err("Can't build the adapter list".into());
        }
        let mut out = VARIANT::default();
        // The variant owns the array from here and frees it with itself.
        let inner = &mut *out.Anonymous.Anonymous;
        inner.vt = VARENUM(VT_ARRAY.0 | VT_VARIANT.0);
        inner.Anonymous.parray = array;
        for (i, name) in names.iter().enumerate() {
            let item = VARIANT::from(BSTR::from(name.as_str()));
            SafeArrayPutElement(array, &(i as i32), (&item as *const VARIANT).cast()).map_err(|e| err("Can't build the adapter list", e))?;
        }
        Ok(out)
    }
}

fn bool_variant(b: bool) -> VARIANT_BOOL {
    if b { VARIANT_TRUE } else { VARIANT_FALSE }
}

pub fn remove_rule(name: &str) -> Result<(), String> {
    let p = policy()?;
    unsafe { rules(&p)?.Remove(&BSTR::from(name)) }.map_err(|e| err("Can't remove the firewall rule", e))
}

pub fn set_rule_enabled(name: &str, enabled: bool) -> Result<(), String> {
    let p = policy()?;
    let rule = unsafe { rules(&p)?.Item(&BSTR::from(name)) }.map_err(|e| err("Can't find the firewall rule", e))?;
    unsafe { rule.SetEnabled(bool_variant(enabled)) }.map_err(|e| err("Can't change the firewall rule", e))
}

/// Switches a rule back on that was switched off earlier, from a name saved where a non-administrator could have edited it.
/// Only an outbound rule is enabled (and only a block rule unless `allow_ok`), so a planted name can't turn on an inbound allow.
pub fn restore_rule(name: &str, allow_ok: bool) -> Result<(), String> {
    let p = policy()?;
    let rule = unsafe { rules(&p)?.Item(&BSTR::from(name)) }.map_err(|e| err("Can't find the firewall rule", e))?;
    unsafe {
        let outbound = rule.Direction().is_ok_and(|d| d == NET_FW_RULE_DIR_OUT);
        let block = rule.Action().is_ok_and(|a| a == NET_FW_ACTION_BLOCK);
        if !outbound || !(block || allow_ok) {
            return Err("Not a rule RustWarden switched off".into());
        }
        rule.SetEnabled(bool_variant(true)).map_err(|e| err("Can't change the firewall rule", e))
    }
}

/// Whether Windows Firewall can tell this service's traffic apart: the service needs its own SID.
/// Services without one share their host's identity, so a rule for them would match the whole host.
pub fn service_has_sid(name: &str) -> Result<bool, String> {
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).map_err(|e| format!("Can't open the Service Control Manager: {e}"))?;
        let short = wide(name);
        let result = match OpenServiceW(scm, PCWSTR(short.as_ptr()), SERVICE_QUERY_CONFIG) {
            Ok(service) => {
                let mut info = SERVICE_SID_INFO { dwServiceSidType: SERVICE_SID_TYPE_NONE };
                let bytes = std::slice::from_raw_parts_mut((&mut info as *mut SERVICE_SID_INFO).cast::<u8>(), size_of::<SERVICE_SID_INFO>());
                let mut needed = 0u32;
                let read = QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, Some(bytes), &mut needed).map_err(|e| format!("Can't read the service {name}: {e}"));
                let _ = CloseServiceHandle(service);
                read.map(|()| info.dwServiceSidType != SERVICE_SID_TYPE_NONE)
            }
            Err(e) => Err(format!("Can't find the service {name}: {e}")),
        };
        let _ = CloseServiceHandle(scm);
        result
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProfileState {
    pub domain: bool,
    pub private: bool,
    pub public: bool,
    /// Bit mask (1 domain, 2 private, 4 public) of the profiles active on this machine right now.
    pub current: i32,
}

impl ProfileState {
    /// Windows Firewall is on for every profile that is currently in use.
    pub fn active_profiles_on(&self) -> bool {
        let on = |bit: i32, enabled: bool| self.current & bit == 0 || enabled;
        on(PROFILE_DOMAIN, self.domain) && on(PROFILE_PRIVATE, self.private) && on(PROFILE_PUBLIC, self.public)
    }
}

pub fn profile_state() -> Result<ProfileState, String> {
    let p = policy()?;
    let get = |profile: i32| unsafe { p.get_FirewallEnabled(NET_FW_PROFILE_TYPE2(profile)) }.map(|b| b.as_bool()).map_err(|e| err("Can't read firewall state", e));
    Ok(ProfileState {
        domain: get(PROFILE_DOMAIN)?,
        private: get(PROFILE_PRIVATE)?,
        public: get(PROFILE_PUBLIC)?,
        current: unsafe { p.CurrentProfileTypes() }.map_err(|e| err("Can't read the active profile", e))?,
    })
}

/// Turns Windows Firewall on for all three profiles. Only called after the user confirmed.
pub fn enable_windows_firewall() -> Result<(), String> {
    let p = policy()?;
    for profile in PROFILES {
        unsafe { p.put_FirewallEnabled(NET_FW_PROFILE_TYPE2(profile), VARIANT_TRUE) }.map_err(|e| err("Can't turn Windows Firewall on", e))?;
    }
    Ok(())
}

/// Default outbound action per profile (true = block), in [`PROFILES`] order.
pub fn default_outbound_blocked() -> Result<[bool; 3], String> {
    let p = policy()?;
    let mut out = [false; 3];
    for (i, profile) in PROFILES.into_iter().enumerate() {
        let action: NET_FW_ACTION = unsafe { p.get_DefaultOutboundAction(NET_FW_PROFILE_TYPE2(profile)) }.map_err(|e| err("Can't read the default action", e))?;
        out[i] = action == NET_FW_ACTION_BLOCK;
    }
    Ok(out)
}

pub fn set_default_outbound_blocked(blocked: [bool; 3]) -> Result<(), String> {
    let p = policy()?;
    for (i, profile) in PROFILES.into_iter().enumerate() {
        let action = if blocked[i] { NET_FW_ACTION_BLOCK } else { NET_FW_ACTION_ALLOW };
        unsafe { p.put_DefaultOutboundAction(NET_FW_PROFILE_TYPE2(profile), action) }.map_err(|e| err("Can't change the default action", e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_profile_check() {
        let on = ProfileState { domain: false, private: true, public: false, current: PROFILE_PRIVATE };
        assert!(on.active_profiles_on());
        let off = ProfileState { current: PROFILE_PUBLIC, ..on };
        assert!(!off.active_profiles_on());
    }

    #[test]
    fn service_sid_query_works_without_administrator() {
        assert!(service_has_sid("no-such-service-for-rustwarden").is_err());
        assert!(service_has_sid("Dnscache").is_ok());
    }

    #[test]
    fn reading_rules_works_without_administrator() {
        // Read-only: finds nothing in a group that cannot exist, but must be able to enumerate.
        let (ours, total) = rules_in_group("RustWarden-test-group-that-does-not-exist").expect("enumerate rules");
        assert!(ours.is_empty());
        assert!(total > 0);
        assert!(profile_state().is_ok());
        assert!(default_outbound_blocked().is_ok());
    }
}
