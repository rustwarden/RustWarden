//! Microsoft Defender folder exclusions, used only for RustWarden's own driver folder and only after the
//! user agreed. The path reaches PowerShell through the environment, never spliced into the script.

use super::qos::powershell;

/// Excludes `folder` from Defender scans, then reads the list back: Tamper Protection can refuse silently.
pub fn add_exclusion(folder: &str) -> Result<(), String> {
    const SCRIPT: &str = "$ErrorActionPreference = 'Stop'; Add-MpPreference -ExclusionPath $env:RW_PATH; \
        if (@((Get-MpPreference).ExclusionPath) -notcontains $env:RW_PATH) { throw 'not applied' }";
    powershell(SCRIPT, &[("RW_PATH", folder)])
        .map(|_| ())
        .map_err(|e| format!("Defender did not accept the exclusion ({e}). Tamper Protection may be on; add the folder in Windows Security > Virus & threat protection > Exclusions."))
}

pub fn remove_exclusion(folder: &str) -> Result<(), String> {
    const SCRIPT: &str = "$ErrorActionPreference = 'Stop'; Remove-MpPreference -ExclusionPath $env:RW_PATH";
    powershell(SCRIPT, &[("RW_PATH", folder)]).map(|_| ())
}
