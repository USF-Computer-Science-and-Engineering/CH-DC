param (
    [string]$action,
    [string]$user
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this script as an administrator to perform actions on Kerberos tickets."
    Exit
}

function Revoke-KerberosTickets {
    param (
        [string]$userSid
    )

    Invoke-Command -ScriptBlock {
        param($userSid)
        Start-Process klist.exe -ArgumentList "/purge", "/user", $userSid -NoNewWindow -PassThru -Wait
    } -ArgumentList $userSid
}

function Revert-KerberosTickets {
    param (
        [string]$userSid
    )

    Invoke-Command -ScriptBlock {
        param($userSid)
        Start-Process klist.exe -ArgumentList "/tgtrenew", "/user", $userSid -NoNewWindow -PassThru -Wait
    } -ArgumentList $userSid
}

function List-KerberosTickets {
    Start-Process klist.exe -ArgumentList "/tickets" -NoNewWindow -PassThru -Wait
}

if ($action -and $user) {
    $userProfiles = Get-WmiObject Win32_UserProfile | Where-Object { $_.SID -eq $user }

    foreach ($userProfile in $userProfiles) {
        $userSid = $userProfile.SID

        switch ($action) {
            "revoke" { Revoke-KerberosTickets -userSid $userSid }
            "revert" { Revert-KerberosTickets -userSid $userSid }
            default { Write-Host "Invalid action. Use -action revoke, -action revert, or -action list." }
        }
    }
} else {
    if ($action -eq "list") {
        List-KerberosTickets
    } else {
        Write-Host "No action specified. Please use -action revoke, -action revert, or -action list, and optionally provide -user for a specific user."
    }
}
