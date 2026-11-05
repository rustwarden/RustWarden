//! Windows QoS policies (`Get/New/Remove-NetQosPolicy`) that cap a program's upload rate. These cmdlets
//! are the only user-mode way to do it, so they run through PowerShell. Every value reaches the script
//! through the environment, never spliced into the command text, and only policies named
//! `RustWarden QoS …` are ever listed or removed. Changing policies needs administrator rights.

use crate::qos::PREFIX;
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::process::Stdio;

pub(super) fn powershell(script: &str, env: &[(&str, &str)]) -> Result<String, String> {
    let mut cmd = super::tool("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]).creation_flags(super::NO_WINDOW).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = super::etw::spawn_own(&mut cmd).map_err(|e| format!("Can't start PowerShell: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("Can't run PowerShell: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(err.lines().find(|l| !l.trim().is_empty()).unwrap_or("PowerShell failed").trim().to_owned())
    }
}

/// What a policy does: rate in bits per second (0 = no throttle) and the DSCP mark (None = unmarked).
pub type Policy = (u64, Option<u8>);

/// Our policies now in Windows by name.
pub fn list() -> Result<HashMap<String, Policy>, String> {
    const SCRIPT: &str = "Get-NetQosPolicy -PolicyStore localhost -ErrorAction Stop | Where-Object { $_.Name.StartsWith($env:RW_PREFIX) } | ForEach-Object { $_.Name + [char]9 + $_.ThrottleRateActionBitsPerSecond + [char]9 + $_.DSCPAction }";
    let text = powershell(SCRIPT, &[("RW_PREFIX", PREFIX)])?;
    Ok(text.lines().filter_map(parse_policy).collect())
}

/// One `name<TAB>rate<TAB>dscp` line; Windows reports "no throttle" and "no DSCP" as -1.
fn parse_policy(line: &str) -> Option<(String, Policy)> {
    let mut f = line.split('\t');
    let name = f.next()?.trim().to_owned();
    let rate = f.next()?.trim().parse::<i64>().ok()?.max(0) as u64;
    let dscp = f.next().and_then(|d| d.trim().parse::<i16>().ok()).and_then(|d| u8::try_from(d).ok());
    Some((name, (rate, dscp)))
}

/// Creates the policy, replacing one of the same name. A rate of 0 means no throttle; `dscp` marks the program's packets.
pub fn apply(name: &str, program: &str, bits_per_second: u64, dscp: Option<u8>) -> Result<(), String> {
    if !name.starts_with(PREFIX) {
        return Err("Not a RustWarden policy name.".into());
    }
    const SCRIPT: &str = "$ErrorActionPreference = 'Stop'; \
        if (Get-NetQosPolicy -Name $env:RW_NAME -PolicyStore localhost -ErrorAction SilentlyContinue) { Remove-NetQosPolicy -Name $env:RW_NAME -PolicyStore localhost -Confirm:$false }; \
        $a = @{ Name = $env:RW_NAME; PolicyStore = 'localhost'; AppPathNameMatchCondition = $env:RW_PATH };         if ([uint64]$env:RW_BPS -gt 0) { $a.ThrottleRateActionBitsPerSecond = [uint64]$env:RW_BPS };         if ($env:RW_DSCP -ne '') { $a.DSCPAction = [int]$env:RW_DSCP };         New-NetQosPolicy @a | Out-Null";
    let dscp = dscp.map(|d| d.to_string()).unwrap_or_default();
    powershell(SCRIPT, &[("RW_NAME", name), ("RW_PATH", program), ("RW_BPS", &bits_per_second.to_string()), ("RW_DSCP", &dscp)]).map(|_| ())
}

pub fn remove(name: &str) -> Result<(), String> {
    if !name.starts_with(PREFIX) {
        return Err("Not a RustWarden policy name.".into());
    }
    const SCRIPT: &str = "$ErrorActionPreference = 'Stop'; Remove-NetQosPolicy -Name $env:RW_NAME -PolicyStore localhost -Confirm:$false";
    powershell(SCRIPT, &[("RW_NAME", name)]).map(|_| ())
}

/// Removes every RustWarden policy in one go; returns how many were there.
pub fn remove_all() -> Result<usize, String> {
    const SCRIPT: &str = "$ErrorActionPreference = 'Stop'; $p = @(Get-NetQosPolicy -PolicyStore localhost | Where-Object { $_.Name.StartsWith($env:RW_PREFIX) }); \
        $p | ForEach-Object { Remove-NetQosPolicy -Name $_.Name -PolicyStore localhost -Confirm:$false }; $p.Count";
    powershell(SCRIPT, &[("RW_PREFIX", PREFIX)]).map(|t| t.trim().parse().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_names_that_are_not_ours() {
        assert!(apply("Other policy", r"C:\a.exe", 1000, None).is_err());
        assert!(remove("Other policy").is_err());
    }

    #[test]
    fn reads_policy_lines_with_and_without_throttle_or_dscp() {
        assert_eq!(parse_policy("RustWarden QoS 1 a.exe	2000000	-1"), Some(("RustWarden QoS 1 a.exe".into(), (2_000_000, None))));
        assert_eq!(parse_policy("RustWarden QoS 2 b.exe	-1	46").unwrap().1, (0, Some(46)));
        assert_eq!(parse_policy("junk"), None);
    }

    #[test]
    fn can_ask_windows_for_our_policies() {
        // Works without administrator rights; a machine without the QoS cmdlets just reports an error.
        if let Ok(map) = list() {
            assert!(map.keys().all(|n| n.starts_with(PREFIX)));
        }
    }
}
