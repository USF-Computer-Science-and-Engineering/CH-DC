[CmdletBinding()]
param(
    [string[]]$e
)

# -----------------------------
# Logging
# -----------------------------
$logPath = Join-Path -Path $PSScriptRoot -ChildPath ("local-password-reset-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message
    Write-Host $line
    try {
        Add-Content -Path $logPath -Value $line -ErrorAction Stop
    } catch {
        Write-Host ("[{0}] [WARN] Failed to write to log file '{1}': {2}" -f $timestamp, $logPath, $_.Exception.Message)
    }
}

function Test-IsAdministrator {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-SecureStringNotEmpty {
    param([Parameter(Mandatory = $true)][Security.SecureString]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        return -not [string]::IsNullOrEmpty($plain)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

$runningOnWindows = ($PSVersionTable.PSEdition -eq "Desktop") -or ($null -ne $IsWindows -and $IsWindows)
if (-not $runningOnWindows) {
    throw "This script only works on Windows because it uses LocalAccounts cmdlets."
}

if (-not (Test-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell session (Run as Administrator)."
}

# -----------------------------
# HARD SAFETY: refuse to run on a Domain Controller
# -----------------------------
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    # DomainRole: 4 = Backup DC, 5 = Primary DC
    if ($cs.DomainRole -in 4,5) {
        Write-Log "SAFETY STOP: This machine is a Domain Controller. Local password reset script will not run on DCs." "ERROR"
        throw "Refusing to run on a Domain Controller."
    }
} catch {
    Write-Log ("SAFETY STOP: Could not confirm domain role. Error: {0}" -f $_.Exception.Message) "ERROR"
    throw
}

# -----------------------------
# Build exclusion set from -e (comma-separated supported)
# Example: -e BTA,administrator
# -----------------------------
$excludeSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if ($e) {
    foreach ($token in $e) {
        foreach ($name in ($token -split ',')) {
            $name = $name.Trim()
            if ($name) { [void]$excludeSet.Add($name) }
        }
    }
}

Write-Log "Starting LOCAL user password reset (NO DOMAIN USERS)."
Write-Log ("Log file: {0}" -f $logPath)

if ($excludeSet.Count -gt 0) {
    Write-Log ("Excluding {0} local username(s): {1}" -f $excludeSet.Count, (($excludeSet | Sort-Object) -join ', ')) "WARN"
}

# -----------------------------
# Ensure LocalAccounts module exists
# -----------------------------
if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
    Write-Log "SAFETY STOP: Get-LocalUser not available. LocalAccounts module is missing on this system." "ERROR"
    throw "Get-LocalUser not found (LocalAccounts module required)."
}

# -----------------------------
# Password input
# -----------------------------
$userPassword = Read-Host "Enter the password to set for all LOCAL users" -AsSecureString
if (-not (Test-SecureStringNotEmpty -SecureString $userPassword)) {
    throw "Password cannot be empty."
}

# -----------------------------
# HARD SAFETY: machine account protections
# - Local machine accounts typically end with '$'
# - Also exclude known built-in/service style accounts conservatively
# -----------------------------
function Is-MachineAccountName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }

    # Primary machine-account indicator
    if ($Name.EndsWith('$')) { return $true }

    # Extra conservative blocks (you said "don't go anywhere near them")
    # These are common non-human principals; adjust if you *really* need them.
    $blocked = @(
        "ANONYMOUS LOGON",
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "DefaultAccount",
        "WDAGUtilityAccount",
        "Guest"
    )

    return $blocked -contains $Name
}

Write-Log "Fetching LOCAL users only (excluding machine accounts and -e exclusions)."

# Grab all local users, then aggressively filter
$localUsers = Get-LocalUser | Where-Object {
    $_.Enabled -eq $true -and
    -not (Is-MachineAccountName $_.Name) -and
    -not $excludeSet.Contains($_.Name)
}

if (-not $localUsers) {
    Write-Log "No eligible local users found after filters. Nothing to change." "WARN"
    return
}

# Additional safety: if any user somehow looks like a machine acct, abort rather than risk it
$machineLike = Get-LocalUser | Where-Object { $_.Name -like '*$' }
if ($machineLike) {
    Write-Log ("SAFETY NOTE: Detected local account(s) ending with `$`: {0}. These will NOT be touched." -f (($machineLike.Name | Sort-Object) -join ", ")) "WARN"
}

foreach ($user in $localUsers) {
    try {
        # Set-LocalUser requires plain text password, so use the supported cmdlet:
        # Set-LocalUser -Password takes SecureString (good)
        Set-LocalUser -Name $user.Name -Password $userPassword -ErrorAction Stop
        Write-Log ("Set password for LOCAL user: {0}" -f $user.Name)
    } catch {
        Write-Log ("Failed to set password for LOCAL user: {0}. Error: {1}" -f $user.Name, $_.Exception.Message) "ERROR"
    }
}

Write-Log "Completed LOCAL user password reset."
