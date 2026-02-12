function Ask-UserYesNo {
    param (
        [string]$Message
    )

    do {
        $response = Read-Host "$Message (Y/N)"
    } until ($response -match '^[YyNn]$')

    return ($response -match '^[Yy]$')
}

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
                
            }
        }
    }
    Search-GPPPasswords


    function Search-AutoLogonSettings {
        Write-Host "Searching for AutoLogon registry settings..." -ForegroundColor Yellow
        $autoLogonKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $autoLogonValues = @("DefaultUserName", "DefaultPassword", "AutoAdminLogon")

        foreach ($value in $autoLogonValues) {
            $regValue = Get-ItemProperty -Path $autoLogonKey -Name $value -ErrorAction SilentlyContinue
            if ($regValue) {
                Write-Host "Found AutoLogon setting: $value = $($regValue.$value)" -ForegroundColor Green
                
            }
        }
    }
    Search-AutoLogonSettings

    if (Ask-UserYesNo "Do you want to disable anonymous access and null sessions? (May mess with WinRM) (Y/N)") {
        $group1Commands = @(
            'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f',
            'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f',
            'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f'
        )
        Apply-GroupedRegistryChanges "Disable Anonymous Access" $group1Commands
    }

    $group2Commands = @(
        'reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f',
        'reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f'
    )
    Apply-GroupedRegistryChanges "LAN Manager Settings" $group2Commands

 
    $group3Commands = @(
        'reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f',
        'reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 0 /f'
    )
    Apply-GroupedRegistryChanges "UAC and Installer Policies" $group3Commands

    if (Ask-UserYesNo "Do you want to enable Protected Process Light (PPL) for LSASS? (May mess with) (Y/N)") {
         $group4Commands = @(
            'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f'
        )
        Apply-GroupedRegistryChanges "Protected Process Light" $group4Commands
    }
    $group4Commands = @(
        'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Protected Process Light" $group4Commands

 
    $group5Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Disable SMBv1 and Enable SMBv2" $group5Commands

    if (Ask-UserYesNo "Do you want to disable NTLMv1 and enforce advanced security settings? (May mess with WinRM) (Y/N)") {
         $group6Commands = @(
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f'
        )
        Apply-GroupedRegistryChanges "Disable NTLMv1 and Enable Advanced Security Settings" $group6Commands
    }


    $group7Commands = @(
        'net user Guest /active:no',
        'net user DefaultAccount /active:no',
        'net user WDAGUtilityAccount /active:no'
    )
    Apply-GroupedRegistryChanges "Remove Guest and Default Accounts" $group7Commands


    $group8Commands = @(
        'auditpol /set /category:* /success:enable /failure:enable'
    )
    Apply-GroupedRegistryChanges "Enable Full Auditing" $group8Commands


    $group9Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f'
    )
    #Apply-GroupedRegistryChanges "Disable Admin Shares" $group9Commands UNCOMMENT TO REMOVEEEEEEEEEEEEE


    function Remove-ShareWriteAccess {
        Write-Host "Removing write access from non-default shares..." -ForegroundColor Yellow
        $shares = Get-SmbShare | Where-Object { $_.Name -notin @("ADMIN$", "C$", "IPC$") }

        foreach ($share in $shares) {
            $shareName = $share.Name
            $sharePath = $share.Path
            Write-Host "Processing share: $shareName ($sharePath)" -ForegroundColor Cyan

       
            Revoke-SmbShareAccess -Name $shareName -AccountName "Everyone" -Force
            Revoke-SmbShareAccess -Name $shareName -AccountName "Users" -Force
            Revoke-SmbShareAccess -Name $shareName -AccountName "Authenticated Users" -Force

        
            Grant-SmbShareAccess -Name $shareName -AccountName "Everyone" -AccessRight Read -Force
            Grant-SmbShareAccess -Name $shareName -AccountName "Users" -AccessRight Read -Force
            Grant-SmbShareAccess -Name $shareName -AccountName "Authenticated Users" -AccessRight Read -Force

            Write-Host "Removed write access for share: $shareName" -ForegroundColor Green
        }
    }
    #Remove-ShareWriteAccess UNCOMMENT TO REMOVEEEEEEEE
    function Remove-WriteAccessOnAllShares {
        Write-Host "Removing write access on all shares..." -ForegroundColor Yellow
    
    
        $shares = Get-SmbShare
    
        foreach ($share in $shares) {
            $shareName = $share.Name
            $sharePath = $share.Path
    
           
            if (-not $sharePath) {
                Write-Host "Skipping share without a path: $shareName" -ForegroundColor Yellow
                continue
            }
    
            Write-Host "Processing share: $shareName ($sharePath)" -ForegroundColor Cyan
    
            try {
                Revoke-SmbShareAccess -Name $shareName -AccountName "Everyone" -Force
                Grant-SmbShareAccess -Name $shareName -AccountName "Everyone" -AccessRight Read -Force
                Write-Host "Removed write access for Everyone on share: $shareName" -ForegroundColor Green
            } catch {
                Write-Host "Failed to modify share permissions for $shareName. Error: $_" -ForegroundColor Red
            }
    
     
            try {
                $acl = Get-Acl -Path $sharePath
    
              
                $acl.SetAccessRuleProtection($true, $false)
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Write", "ContainerInherit,ObjectInherit", "None", "Deny")
                $acl.AddAccessRule($rule)
    
             
                Set-Acl -Path $sharePath -AclObject $acl
                Write-Host "Removed write access for Everyone on NTFS path: $sharePath" -ForegroundColor Green
            } catch {
                Write-Host "Failed to modify NTFS permissions for $sharePath. Error: $_" -ForegroundColor Red
            }
        }
    
        Write-Host "Write access removed on all shares." -ForegroundColor Cyan
    }
    
  
    #Remove-WriteAccessOnAllShares UNCOMMENT TO REMOVE THE ACCESSS!!!!!!!!!!!!!

    if (Ask-UserYesNo "Do you want to enable Credential Guard? (May mess with WinRM) (Y/N)") {
         $group10Commands = @(
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f',
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v HypervisorEnforcedCodeIntegrity /t REG_DWORD /d 1 /f'
        )
        Apply-GroupedRegistryChanges "Enable Credential Guard" $group10Commands
    }


    $group12Commands = @(
        'reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f'
    )
    Apply-GroupedRegistryChanges "Enable PowerShell Logging" $group12Commands

   
    $group13Commands = @(
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f', 
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerSigning /t REG_DWORD /d 2 /f', 
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPEnforceChannelBinding /t REG_DWORD /d 1 /f', 
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPDisableSimplePwd /t REG_DWORD /d 1 /f' 
    )
    Apply-GroupedRegistryChanges "LDAP Signing and Hardening" $group13Commands

    Write-Host "Credential Hardening completed. A reboot is required to apply all changes." -ForegroundColor Cyan
}

CredHardening