# Modified CredHardening.ps1 with additional hardenings and option A support

function CredHardening {
    param (
        [switch]$YesToAll
    )

    function Apply-GroupedRegistryChanges {
        param (
            [string]$GroupName,
            [array]$Commands
        )

        Write-Host "Group: $GroupName" -ForegroundColor Yellow
        if (-not $YesToAll -and -not $global:ApplyAll) {
            $confirmation = Read-Host "Do you want to apply these changes? (Y/A/N)"
            if ($confirmation -eq 'A') {
                $global:ApplyAll = $true
            } elseif ($confirmation -ne 'Y') {
                Write-Host "Skipped changes for $GroupName." -ForegroundColor Yellow
                return
            }
        }

        foreach ($command in $Commands) {
            Invoke-Expression $command
        }
        Write-Host "Applied changes for $GroupName." -ForegroundColor Green
    }

    Write-Host "Starting Credential Hardening..." -ForegroundColor Cyan

    # Group: Search for GPP Passwords
    function Search-GPPPasswords {
        Write-Host "Searching for GPP passwords..." -ForegroundColor Yellow
        $fqdn = (Get-WmiObject Win32_ComputerSystem).Domain
        $sysvolPath = "\\$fqdn\SYSVOL\$fqdn\Policies"

        if (-not (Test-Path $sysvolPath)) {
            Write-Host "SYSVOL path not found: $sysvolPath" -ForegroundColor Red
            return
        }

        Get-ChildItem -Path $sysvolPath -Recurse -Filter "*.xml" | ForEach-Object {
            $content = Get-Content $_.FullName
            if ($content -match "<cpassword>") {
                Write-Host "Found GPP password in file: $($_.FullName)" -ForegroundColor Green
                # Take appropriate action, such as deleting or securing the file
            }
        }
    }
    Search-GPPPasswords

    # Group: Search for Registry AutoLogon Settings
    function Search-AutoLogonSettings {
        Write-Host "Searching for AutoLogon registry settings..." -ForegroundColor Yellow
        $autoLogonKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $autoLogonValues = @("DefaultUserName", "DefaultPassword", "AutoAdminLogon")

        foreach ($value in $autoLogonValues) {
            $regValue = Get-ItemProperty -Path $autoLogonKey -Name $value -ErrorAction SilentlyContinue
            if ($regValue) {
                Write-Host "Found AutoLogon setting: $value = $($regValue.$value)" -ForegroundColor Green
                # Take action to remove or secure the value if necessary
            }
        }
    }
    Search-AutoLogonSettings
    # Group 1: Anonymous Access Restrictions

    $group1Commands = @(
    'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f',
    'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f',
    'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Disable Anonymous Access" $group1Commands

    # Group 2: LAN Manager Settings
    $group2Commands = @(
        'reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f',
        'reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f'
    )
    Apply-GroupedRegistryChanges "LAN Manager Settings" $group2Commands

    # Group 3: User Account Control and Installer Policies
    $group3Commands = @(
        'reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f',
        'reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 0 /f'
    )
    Apply-GroupedRegistryChanges "UAC and Installer Policies" $group3Commands

    # Group 4: Protected Process Light
    $group4Commands = @(
        'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Protected Process Light" $group4Commands

    $group5Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Disable SMBv1" $group5Commands

    $group6Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "NoLMHash" /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LMCompatibilityLevel" /t REG_DWORD /d 5 /f'
    )
    Apply-GroupedRegistryChanges "Disable NTLMv1 and Enable Advanced Security Settings" $group6Commands

    $group7Commands = @(
        'Apply-RemChanges'
    )
    Apply-GroupedRegistryChanges "Apply Additional Security Settings" $group7Commands

    # Group 8: Remove Guest and Default Accounts
    $group8Commands = @(
        'net user Guest /active:no',
        'net user DefaultAccount /active:no',
        'net user WDAGUtilityAccount /active:no'
    )
    Apply-GroupedRegistryChanges "Remove Guest and Default Accounts" $group8Commands

    # Group 9: Enable Full Auditing
    $group9Commands = @(
        'auditpol /set /category:* /success:enable /failure:enable'
    )
    Apply-GroupedRegistryChanges "Enable Full Auditing" $group9Commands

    # Group 10: Disable Admin Shares
    $group10Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f',
        'reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f'
    )
    Apply-GroupedRegistryChanges "Disable Admin Shares" $group10Commands

    # Group 12: Disable Print Driver Installs
    $group12Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Disable Print Driver Installs" $group12Commands

    # Group 13: Local Account Blank Passwords
    $group13Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Local Account Blank Passwords" $group13Commands

    # Group 14: Enable Full UAC
    $group14Commands = @(
        'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Enable Full UAC" $group14Commands

    # Group 15: Enable Installer Detections
    $group15Commands = @(
        'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Enable Installer Detections" $group15Commands

    # Group 16: Anon Enumeration Prevention
    $group16Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Anon Enumeration Prevention" $group16Commands

    # Group 17: Domain Credential Storing
    $group17Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v disabledomaincreds /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Domain Credential Storing" $group17Commands

    # Group 18: No Permissions to Anons
    $group18Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f'
    )
    Apply-GroupedRegistryChanges "No Permissions to Anons" $group18Commands

    # Group 19: SMB Strengtheners
    $group19Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f'
        #'reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f'
    )
    Apply-GroupedRegistryChanges "SMB Strengtheners" $group19Commands

    # Group 20: Enable SMB Signing
    $group20Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Rdr\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Rdr\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Enable SMB Signing" $group20Commands

    # Group 21: Disable Floppy Disk Remoting
    $group21Commands = @(
        'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Disable Floppy Disk Remoting" $group21Commands

    # Group 22: Enable LSASS Memory Protection
    $group22Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Enable LSASS Memory Protection" $group22Commands

    # Group 23: Enable Credential Guard
    $group23Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Enable Credential Guard" $group23Commands

    # Group 24: Disable Plain Text Passwords in LSASS
    $group24Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f'
    )
    Apply-GroupedRegistryChanges "Disable Plain Text Passwords in LSASS" $group24Commands

    # Group 25: Enable PowerShell Logging
    $group25Commands = @(
        'reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Enable PowerShell Logging" $group25Commands

    Write-Host "Credential Hardening completed." -ForegroundColor Cyan
}

# Run the function with -YesToAll if needed
CredHardening
