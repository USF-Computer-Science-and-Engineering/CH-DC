Install-Module PersistenceSniper
Import-Module PersistenceSniper 

param (
    [string]$cspath
)

if (-not (Test-Path -Path $cspath)) {
    Write-Host "pick a betta path: $cspath"
    exit 1
}

$persistenceMechanisms = Import-Csv -Path $cspath

foreach ($item in $persistenceMechanisms) {
    switch ($item.Technique) {
        "Service Control Manager Security Descriptor Manipulation" {
            Write-Host "Handling Service Control Manager manipulation for $($item.Hostname)"
        }

        "BootExecute Binary" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name $item.Value -Force -ErrorAction SilentlyContinue
                Write-Host "Removed BootExecute binary: $($item.Path)\$($item.Value)"
            }
        }

        "App Paths" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name "(Default)" -Force -ErrorAction SilentlyContinue
                Write-Host "Removed App Paths entry: $($item.Path)"
            }
        }

        "Windows Service" {
            if (Get-Service -Name $item.Path -ErrorAction SilentlyContinue) {
                Stop-Service -Name $item.Path -Force -ErrorAction SilentlyContinue
                sc.exe delete $item.Path
                Write-Host "Removed service: $($item.Path)"
            }
        }

        "Run Key" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name $item.Value -Force -ErrorAction SilentlyContinue
                Write-Host "Removed Run Key: $($item.Path)\$($item.Value)"
            }
        }

        "RunOnce Key" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name $item.Value -Force -ErrorAction SilentlyContinue
                Write-Host "Removed RunOnce Key: $($item.Path)\$($item.Value)"
            }
        }

        "Image File Execution Options" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name "Debugger" -Force -ErrorAction SilentlyContinue
                Write-Host "Removed Image File Execution Options debugger: $($item.Path)"
            }
        }

        "Command Prompt AutoRun" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name "AutoRun" -Force -ErrorAction SilentlyContinue
                Write-Host "Removed Command Prompt AutoRun: $($item.Path)"
            }
        }

        "Winlogon Userinit" {
            if (Test-Path -Path $item.Path) {
                Set-ItemProperty -Path $item.Path -Name "Userinit" -Value "C:\Windows\system32\userinit.exe," -ErrorAction SilentlyContinue
                Write-Host "Restored default Winlogon Userinit: $($item.Path)"
            }
        }

        "Winlogon Shell" {
            if (Test-Path -Path $item.Path) {
                Set-ItemProperty -Path $item.Path -Name "Shell" -Value "explorer.exe" -ErrorAction SilentlyContinue
                Write-Host "Restored default Winlogon Shell: $($item.Path)"
            }
        }

        "AppCertDlls DLL Injection" {
            if (Test-Path -Path $item.Path) {
                Get-ItemProperty -Path $item.Path | ForEach-Object {
                    Remove-ItemProperty -Path $item.Path -Name $_.PSChildName -Force -ErrorAction SilentlyContinue
                }
                Write-Host "Removed AppCertDlls DLL Injection: $($item.Path)"
            }
        }

        "Startup Folder" {
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\*" -Force -ErrorAction SilentlyContinue
            Write-Host "Cleared Startup Folder for current user"
        }

        "WMI Subscriptions" {
            Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Remove-WmiObject
            Get-WmiObject -Namespace root\subscription -Class __EventFilter | Remove-WmiObject
            Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
            Write-Host "Removed all WMI Subscriptions"
        }

        "Scheduled Tasks" {
            Get-ScheduledTask | Where-Object { $_.TaskPath -like "*Malicious*" } | Unregister-ScheduledTask -Confirm:$false
            Write-Host "Removed malicious scheduled tasks"
        }

        "LSA Extensions DLL" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name "Extensions" -Force -ErrorAction SilentlyContinue
                Write-Host "Removed LSA Extensions DLL"
            }
        }

        "Office Templates" {
            Remove-Item "$env:APPDATA\Microsoft\Templates\*.dotm" -Force -ErrorAction SilentlyContinue
            Write-Host "Removed malicious Office Templates"
        }

        "PowerShell Profiles" {
            Remove-Item "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1" -Force -ErrorAction SilentlyContinue
            Write-Host "Removed malicious PowerShell profiles"
        }

        "Explorer Load" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name "Load" -Force -ErrorAction SilentlyContinue
                Write-Host "Removed malicious Explorer Load"
            }
        }

        "Winlogon MPNotify" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name "mpnotify" -Force -ErrorAction SilentlyContinue
                Write-Host "Removed malicious Winlogon MPNotify"
            }
        }

        "AMSI Providers" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name "(Default)" -Force -ErrorAction SilentlyContinue
                Write-Host "Removed malicious AMSI Providers"
            }
        }

        "Netsh Helper DLL" {
            if (Test-Path -Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name "(Default)" -Force -ErrorAction SilentlyContinue
                Write-Host "Removed malicious Netsh Helper DLL"
            }
        }

        default {
            Write-Host "Unknown technique: $($item.Technique)"
        }
    }
}

Write-Host "Remediation completed."
