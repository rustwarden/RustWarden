//! Which Windows services run in which process, from the Service Control Manager. A service's
//! traffic is attributed to its svchost.exe, so the svchost pid alone doesn't say which service sent it.

use std::collections::HashMap;
use windows::Win32::Foundation::ERROR_MORE_DATA;
use windows::Win32::System::Services::{CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, SC_ENUM_PROCESS_INFO, SERVICE_STATE_ALL, SERVICE_WIN32};
use windows::core::PCWSTR;

/// SC_MANAGER_ENUMERATE_SERVICE: the access right needed to list services.
const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    /// Short name, as `sc.exe` and the registry use it (`wuauserv`).
    pub name: String,
    /// Friendly name shown in services.msc (`Windows Update`).
    pub display: String,
}

/// Services by the pid of the process hosting them. Only services that are running have a pid.
pub fn by_pid() -> Result<HashMap<u32, Vec<Service>>, String> {
    let mut out: HashMap<u32, Vec<Service>> = HashMap::new();
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE).map_err(|e| format!("Can't open the Service Control Manager: {e}"))?;
        // Word-aligned, since the buffer holds pointers and structs; viewed as bytes for the API.
        let mut store: Vec<usize> = vec![0; 16 * 1024];
        let mut resume = 0u32;
        let result = loop {
            let mut need = 0u32;
            let mut count = 0u32;
            let bytes = std::slice::from_raw_parts_mut(store.as_mut_ptr().cast::<u8>(), store.len() * size_of::<usize>());
            let rc = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, Some(bytes), &mut need, &mut count, Some(&mut resume), PCWSTR::null());
            let entries = store.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>();
            for i in 0..count as usize {
                let e = &*entries.add(i);
                let pid = e.ServiceStatusProcess.dwProcessId;
                if pid == 0 {
                    continue;
                }
                let name = e.lpServiceName.to_string().unwrap_or_default();
                let display = e.lpDisplayName.to_string().unwrap_or_default();
                out.entry(pid).or_default().push(Service { name, display });
            }
            match rc {
                Ok(()) => break Ok(()),
                Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => {
                    // Nothing fit: grow the buffer to what the API asked for, then go on from the resume handle.
                    if count == 0 {
                        store.resize((need as usize).div_ceil(size_of::<usize>()) + 1024, 0);
                    }
                }
                Err(e) => break Err(format!("Can't list services: {e}")),
            }
        };
        let _ = CloseServiceHandle(scm);
        result.map(|()| out)
    }
}

/// The map key part and the label for the services in one process. One service keeps its own
/// name: `Windows Update (wuauserv)`. Several services share the host, so the label lists them.
pub fn label(services: &[Service]) -> Option<(String, String)> {
    let mut names: Vec<&str> = services.iter().map(|s| s.name.as_str()).collect();
    if names.is_empty() {
        return None;
    }
    names.sort_by_key(|n| n.to_lowercase());
    let key = names.iter().map(|n| n.to_lowercase()).collect::<Vec<_>>().join("+");
    let text = match services {
        [one] if one.display.trim().is_empty() => one.name.clone(),
        [one] => format!("{} ({})", one.display.trim(), one.name),
        _ => format!("Shared host ({})", names.join(", ")),
    };
    Some((key, text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(name: &str, display: &str) -> Service {
        Service { name: name.into(), display: display.into() }
    }

    #[test]
    fn one_service_is_named_with_its_short_name() {
        let (key, text) = label(&[svc("wuauserv", "Windows Update")]).unwrap();
        assert_eq!(key, "wuauserv");
        assert_eq!(text, "Windows Update (wuauserv)");
    }

    #[test]
    fn a_service_without_display_name_uses_its_short_name() {
        assert_eq!(label(&[svc("BITS", "")]).unwrap().1, "BITS");
    }

    #[test]
    fn shared_hosts_are_keyed_in_a_stable_order() {
        let a = label(&[svc("mpssvc", "Windows Defender Firewall"), svc("BFE", "Base Filtering Engine")]).unwrap();
        let b = label(&[svc("BFE", "Base Filtering Engine"), svc("mpssvc", "Windows Defender Firewall")]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.0, "bfe+mpssvc");
        assert_eq!(a.1, "Shared host (BFE, mpssvc)");
    }

    #[test]
    fn no_services_no_label() {
        assert!(label(&[]).is_none());
    }

    #[test]
    fn lists_running_services() {
        // Any Windows machine runs services; the RPC server (RpcSs) is always among them.
        let map = by_pid().expect("enumerate services");
        assert!(map.values().flatten().any(|s| s.name.eq_ignore_ascii_case("RpcSs")));
    }
}
