Install-Module PersistenceSniper
Import-Module PersistenceSniper 


$OutputCsv = "C:\tools\logs\findings.csv"
$LogFile = "C:\tools\logs\rm-per.log"
$ModuleName = "PersistenceSniper"


$logDirectory = Split-Path $LogFile -Parent
if (!(Test-Path $logDirectory)) { New-Item -ItemType Directory -Path $logDirectory | Out-Null }

function Write-Log {
    param (
        [string]$Message
    )
    "$((Get-Date -Format "yyyy-MM-dd HH:mm:ss")) - $Message" | Out-File -FilePath $LogFile -Append
    Write-Output $Message
}

try {
    Import-Module $ModuleName -ErrorAction Stop
    Write-Log "Module loaded."
}
catch {
    Write-Log "ERROR: Module load failed."
    exit
}


Write-Log "Running PersistenceSniper..."
Find-AllPersistence | Export-Csv -Path $OutputCsv -NoTypeInformation
Write-Log "Findings exported to $OutputCsv"

Write-Output "Review CSV and type 'continue' when ready."
do {
    $userInput = Read-Host "Type 'continue' to proceed"
} while ($userInput -ne 'continue')

if (!(Test-Path $OutputCsv)) {
    Write-Log "ERROR: CSV not found."
    exit
}
$findings = Import-Csv -Path $OutputCsv


function Remove-IFEO {
    param (
        [string]$Path
    )
    Write-Log "Remediating IFEO Path: '$Path'"
    Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
}

function Clear-BootExecute {
    Write-Log "Clearing BootExecute Value"
    Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name BootExecute -ErrorAction SilentlyContinue
}

function Remove-NetshDLL {
    param (
        [string]$Name
    )
    Write-Log "Removing Netsh Helper DLL: '$Name'"
    netsh add helper "$Name" remove | Out-Null
}

function Clear-LogonScripts {
    param (
        [string]$ScriptPath
    )
    Write-Log "Clearing Logon Script Path: '$ScriptPath'"
    Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
}

function Clear-UserInit {
    param (
        [string]$Path
    )
    Write-Log "Clearing UserInit Value in Path: '$Path'"
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Userinit -ErrorAction SilentlyContinue
}

function Remove-RunKeys {
    param (
        [string]$Path
    )
    Write-Log "Removing Registry Run Keys in Path: '$Path'"
    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
}

function Disable-ScheduledTask {
    param (
        [string]$TaskName
    )
    Write-Log "Disabling Scheduled Task: '$TaskName'"
    Get-ScheduledTask -TaskName $TaskName | Disable-ScheduledTask -ErrorAction SilentlyContinue
}

function Unregister-WMI {
    param (
        [string]$EventFilterName,
        [string]$Namespace = "root\subscription" 
    )
    Write-Log "Unregistering WMI Event Filter: '$EventFilterName' in Namespace: '$Namespace'"
    Get-WmiObject __EventFilter -Namespace $Namespace | Where-Object {$_.Name -eq $EventFilterName} | Remove-WmiObject -ErrorAction SilentlyContinue
}

function Remove-Service {
    param (
        [string]$ServiceName
    )
    Write-Log "Removing Service: '$ServiceName'"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName 
}

function Clear-AppInitDLLs {
    param (
        [string]$RegistryPath
    )
    Write-Log "Clearing AppInit_DLLs Value in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'AppInit_DLLs' -ErrorAction SilentlyContinue
}

function Remove-LSAProviders {
    param (
        [string]$ProviderName
    )
    Write-Log "Removing LSA Provider: '$ProviderName'"
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name $ProviderName -ErrorAction SilentlyContinue
}

function Remove-AppCertDLLs {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing AppCertDLLs Value in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'AppCertDlls' -ErrorAction SilentlyContinue
}

function Remove-AccessibilityDebugger {
    param (
        [string]$DebuggerName
    )
    Write-Log "Removing Accessibility Debugger: '$DebuggerName'"
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$DebuggerName" -Name Debugger -ErrorAction SilentlyContinue
}

function Remove-RunKey { 
    param (
        [string]$Path,
        [string]$Name
    )
    Write-Log "Removing specific Run Key Name: '$Name' in Path: '$Path'"
    Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
}

function Remove-RunOnceKey { 
    param (
        [string]$Path,
        [string]$Name
    )
    Write-Log "Removing specific RunOnce Key Name: '$Name' in Path: '$Path'"
    Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
}

function Clear-NLDPDllPath {
    param (
        [string]$Path
    )
    Write-Log "Clearing Natural Language DLL Path Location in: '$Path'"
    Remove-ItemProperty -Path $Path -Name 'Location' -Force -ErrorAction SilentlyContinue
}

function Remove-LSAExtensions {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing LSA Extensions Value in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'Extensions' -Force -ErrorAction SilentlyContinue
}

function Clear-WinlogonUserInit {
    param (
        [string]$RegistryPath
    )
    Write-Log "Clearing Winlogon Userinit Value in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'Userinit' -Force -ErrorAction SilentlyContinue
}

function Clear-WinlogonShell {
    param (
        [string]$RegistryPath
    )
    Write-Log "Clearing Winlogon Shell Value in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'Shell' -Force -ErrorAction SilentlyContinue
}

function Remove-LSAPackages {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing LSA Security Packages Value in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'Security Packages' -Force -ErrorAction SilentlyContinue
}

function Remove-StartupItem {
    param (
        [string]$FilePath
    )
    Write-Log "Removing Startup Item: '$FilePath'"
    Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
}

function Remove-RegistryItem { 
    param (
        [string]$Path,
        [string]$Name
    )
    Write-Log "Removing Registry Item Name: '$Name' in Path: '$Path'"
    Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
}

function Clear-ExplorerHijack {
    param (
        [string]$Path
    )
    Write-Log "Clearing Explorer Hijack in Path: '$Path'"
    Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
}

function Remove-PowerShellProfile {
    Write-Log "Removing PowerShell Profile"
    Remove-Item "$HOME\Documents\WindowsPowerShell\profile.ps1" -Force -ErrorAction SilentlyContinue
}

function Remove-RIDHijack { # Updated function - now logs a warning and advises manual review.
    param (
        [string]$Path
    )
    Write-Log "WARNING: RID Hijacking Detected - Manual Remediation Required."
    Write-Log "Technique: RID Hijacking, Details: $($Path)" # Log the details for manual review
    Write-Log "Automated remediation for RID Hijacking is complex and potentially risky."
    Write-Log "Please manually investigate and remediate RID Hijacking as per security best practices."
    # No automated removal action in this version.
}

function Remove-OfficeTemplate {
    param (
        [string]$FilePath
    )
    Write-Log "Removing Office Template: '$FilePath'"
    Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
}

function Clear-AMSIProviders {
    param (
        [string]$RegistryPath
    )
    Write-Log "Clearing AMSI Providers in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name '(Default)' -Force -ErrorAction SilentlyContinue
}

function Remove-TerminalServicesProgram {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing Terminal Services Initial Program in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'InitialProgram' -Force -ErrorAction SilentlyContinue
}

function Remove-ScreensaverHijack {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing Screensaver Hijack in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'SCRNSAVE.EXE' -Force -ErrorAction SilentlyContinue
}

function Remove-NetshHelperPath { 
    param (
        [string]$Path
    )
    Write-Log "Removing Netsh Helper by Path: '$Path'"
    Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
}

function Remove-TelemetryController {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing Telemetry Controller in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'Command' -Force -ErrorAction SilentlyContinue
}

function Remove-SilentExitMonitor {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing Silent Exit Monitor in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'MonitorProcess' -Force -ErrorAction SilentlyContinue
}

function Remove-AppInitDLL {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing specific AppInit_DLL Value in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'AppInit_DLLs' -Force -ErrorAction SilentlyContinue
}

function Remove-PlatformExecute {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing PlatformExecute Value in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'PlatformExecute' -Force -ErrorAction SilentlyContinue
}

function Remove-SetupExecute {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing SetupExecute Value in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'SetupExecute' -Force -ErrorAction SilentlyContinue
}

function Remove-BootVerification {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing Boot Verification Hijack in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'ImagePath' -Force -ErrorAction SilentlyContinue
}

function Remove-CompatTelRunner {
    param (
        [string]$RegistryPath
    )
    Write-Log "Removing CompatTelRunner Hijack in Path: '$RegistryPath'"
    Remove-ItemProperty -Path $RegistryPath -Name 'TelemetryController' -Force -ErrorAction SilentlyContinue
}

function Remove-ErrorHandlerCMD {
    param (
        [string]$FilePath
    )
    Write-Log "Removing ErrorHandler.cmd Hijack File: '$FilePath'"
    Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
}

function Remove-GhostTask {
    param (
        [string]$Path
    )
    Write-Log "Removing Ghost Task in Path: '$Path'"
    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
}

function Reset-SCMSecurityDescriptor {
    Write-Log "Resetting Service Control Manager Security Descriptor to Default"

    $defaultSddl = "D:(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AU)"

    try {
        $scm = Get-WmiObject -Class Win32_SCConfig
        $result = $scm.ChangeSecurity($defaultSddl)

        if ($result.ReturnValue -eq 0) {
            Write-Log "Successfully reset SCM Security Descriptor."
        } else {
            Write-Log "ERROR: Failed to reset SCM Security Descriptor. Return code: $($result.ReturnValue)"
            Write-Log "Manual remediation of SCM Security Descriptor may be required."
        }
    }
    catch {
        Write-Log "EXCEPTION occurred while trying to reset SCM Security Descriptor: $_"
        Write-Log "Manual remediation of SCM Security Descriptor is likely required."
    }
}


foreach ($finding in $findings) {
    Write-Log "Remediating: $($finding.Technique) - $($finding.Details)"
    switch ($finding.Technique) {
        "Image File Execution Options"                                 { Remove-IFEO -Path $finding.Path }
        "BootExecute"                                                  { Clear-BootExecute }
        "BootExecute Binary"                                             { Clear-BootExecute } # ADDED: Handle "Binary" variation
        "Netsh Helper DLL"                                            { Remove-NetshDLL -Name $finding.Name } # Assuming $finding.Name is available for Netsh Helper
        "Logon Script"                                                 { Clear-LogonScripts -ScriptPath $finding.ScriptPath }
        "UserInit"                                                     { Clear-UserInit -Path $finding.Path }
        "Winlogon Userinit"                                            { Clear-WinlogonUserInit -RegistryPath $finding.Path }
        "Winlogon Userinit Property"                                   { Clear-WinlogonUserInit -RegistryPath $finding.Path } # ADDED: Handle "Property" variation
        "Winlogon Shell"                                               { Clear-WinlogonShell -RegistryPath $finding.Path }
        "Winlogon Shell Property"                                      { Clear-WinlogonShell -RegistryPath $finding.Path } # ADDED: Handle "Property" variation
        "Registry Run Key"                                             { Remove-RunKeys -Path $finding.Path }
        "Scheduled Task"                                               { Disable-ScheduledTask -TaskName $finding.TaskName }
        "WMI Event Subscription"                                       { Unregister-WMI -EventFilterName $finding.EventName } # Corrected parameter name
        "Service"                                                      { Remove-Service -ServiceName $finding.ServiceName } # Corrected parameter name
        "AppInit DLLs"                                                { Clear-AppInitDLLs -RegistryPath $finding.RegistryPath } # Corrected parameter name
        "AppInit DLL injection"                                        { Clear-AppInitDLLs -RegistryPath $finding.RegistryPath } # ADDED: Handle "injection" variation
        "LSA Providers"                                                { Remove-LSAProviders -ProviderName $finding.ProviderName } # Corrected parameter name
        "AppCertDLLs"                                                  { Remove-AppCertDLLs -RegistryPath $finding.Path } # Corrected parameter name
        "Accessibility Debugger"                                     { Remove-AccessibilityDebugger -DebuggerName $finding.DebuggerName } # Corrected parameter name
        "Accessibility Tools Backdoor"                                 { Remove-AccessibilityDebugger -DebuggerName $finding.DebuggerName } # ADDED: Handle "Backdoor" variation
        "Run Key"                                                      { if ($finding.Name) { Remove-RunKey -Path $finding.Path -Name $finding.Name } else { Write-Log "Warning: Run Key Name missing for $($finding.Details)" } } # Handle specific Run Key with Name if available
        "RunOnce Key"                                                  { if ($finding.Name) { Remove-RunOnceKey -Path $finding.Path -Name $finding.Name } else { Write-Log "Warning: RunOnce Key Name missing for $($finding.Details)" } } # Handle specific RunOnce Key with Name if available
        "Natural Language DLL Path"                                    { Clear-NLDPDllPath -Path $finding.Path }
        "LSA Extensions"                                               { Remove-LSAExtensions -RegistryPath $finding.Path } # Corrected parameter name
        "LSA Security Packages"                                        { Remove-LSAPackages -RegistryPath $finding.Path } # Existing case
        "LSA Security Package DLL"                                     { Remove-LSAPackages -RegistryPath $finding.Path } # ADDED: Handle "DLL" variation
        "Startup Folder Item"                                          { Remove-StartupItem -FilePath $finding.FilePath }
        "Startup Folder"                                               { Remove-StartupItem -FilePath $finding.FilePath } # Deduplicated - Same action for both "Startup Folder Item" and "Startup Folder"
        "Explorer Hijacking"                                           { Clear-ExplorerHijack -Path $finding.Path }
        "PowerShell Profile"                                           { Remove-PowerShellProfile }
        "RID Hijacking"                                                { Remove-RIDHijack -Path $finding.Path } # Updated to log warning and manual review message
        "Office Templates"                                             { Remove-OfficeTemplate -FilePath $finding.FilePath }
        "AMSI Providers"                                               { Clear-AMSIProviders -RegistryPath $finding.Path } # Corrected Parameter
        "Suborner Technique"                                           { Write-Log "Suborner Technique detected - Manual review advised." }
        "Terminal Services Program"                                    { Remove-TerminalServicesProgram -RegistryPath $finding.Path } # Corrected Parameter
        "Screensaver Hijack"                                          { Remove-ScreensaverHijack -RegistryPath $finding.Path } # Corrected Parameter
        "Suspicious Screensaver Program"                                { Remove-ScreensaverHijack -RegistryPath $finding.Path } # ADDED: Handle "Suspicious Screensaver Program" variation
        "Silent Exit Monitor"                                          { Remove-SilentExitMonitor -RegistryPath $finding.Path } # Corrected Parameter
        "Silent Process Exit Monitor"                                  { Remove-SilentExitMonitor -RegistryPath $finding.Path } # ADDED: Handle "Process Exit" variation
        "Netsh Helper DLL Path"                                        { Remove-NetshHelperPath -Path $finding.Path } # Added case for removing by Path, assuming path finding is available.
        "Telemetry Controller"                                         { Remove-TelemetryController -RegistryPath $finding.Path } # Corrected Parameter
        "AppInit DLL"                                                 { Remove-AppInitDLL -RegistryPath $finding.Path } # Corrected Parameter and using singular function
        "PlatformExecute"                                              { Remove-PlatformExecute -RegistryPath $finding.Path } # Corrected Parameter
        "SetupExecute"                                                 { Remove-SetupExecute -RegistryPath $finding.RegistryPath } # Corrected Parameter
        "Boot Verification Hijack"                                     { Remove-BootVerification -RegistryPath $finding.Path } # Corrected Parameter
        "CompatTelRunner Hijack"                                       { Remove-CompatTelRunner -RegistryPath $finding.Path } # Corrected Parameter
        "ErrorHandler.cmd Hijack"                                      { Remove-ErrorHandlerCMD -FilePath $finding.FilePath }
        "GhostTask"                                                    { Remove-GhostTask -Path $finding.Path }
        "Service Control Manager Security Descriptor Manipulation"     { Reset-SCMSecurityDescriptor } # ADDED: Handle SCM Security Descriptor
        default                                                        { Write-Log "No remediation defined for: $($finding.Technique)" }
    }
}

Write-Log "All remediation steps completed. Log file: $LogFile"
Write-Output "Remediation completed. Check log at $LogFile"