Start-Job -ScriptBlock {
    $servicesToMonitor = @("DNS Server", "sshd", "ssh-agent", "Microsoft FTP Service")  # DNS, SSH, FTP

    while ($true) {
        foreach ($serviceName in $servicesToMonitor) {
            $service = Get-Service -Name $serviceName
            if ($service.Status -eq "Stopped") {
                Start-Service -Name $serviceName
                Write-Output "$serviceName service was stopped and has now been started."
            }
        }
        Start-Sleep -Seconds 10  # Check every 10 seconds
    }
}

# Stop the Print Spooler service
Stop-Service -Name Spooler -Force

# Disable the Print Spooler service
Set-Service -Name Spooler -StartupType Disabled

Write-Host "Print Spooler service has been stopped and disabled."

reg.exe add HKLM\SYSTEM\CurrentControlSet\Control /v DisableRemoteScmEndpoints /t REG_DWORD /d 1

Write-Host "SCM defeaned to remote management."