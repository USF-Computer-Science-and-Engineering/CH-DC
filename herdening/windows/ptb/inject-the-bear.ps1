$ErrorActionPreference = 'SilentlyContinue'

Write-Host '=== Basic Host Information ===' -ForegroundColor Cyan

$computerSystem = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem

$hostname = $env:COMPUTERNAME
Write-Host "Hostname: $hostname"

$activeAdapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' }

if ($activeAdapters) {
    $ipAddresses = $activeAdapters | ForEach-Object { $_.IPv4Address.IPAddress } | Sort-Object -Unique
    Write-Host ("IP Address(es): {0}" -f ($ipAddresses -join ', '))
} else {
    Write-Host 'IP Address(es): Not found'
}

$macAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.MacAddress }
if ($macAdapters) {
    $macAddresses = $macAdapters | Select-Object -ExpandProperty MacAddress -Unique
    Write-Host ("MAC Address(es): {0}" -f ($macAddresses -join ', '))
} else {
    Write-Host 'MAC Address(es): Not found'
}

$isDomainJoined = [bool]$computerSystem.PartOfDomain
Write-Host ("Domain Joined: {0}" -f $isDomainJoined)

if ($isDomainJoined) {
    Write-Host ("Domain: {0}" -f $computerSystem.Domain)
} else {
    Write-Host 'Domain: N/A'
}

$domainRoleMap = @{
    0 = 'Standalone Workstation'
    1 = 'Member Workstation'
    2 = 'Standalone Server'
    3 = 'Member Server'
    4 = 'Backup Domain Controller'
    5 = 'Primary Domain Controller'
}

$domainRole = [int]$computerSystem.DomainRole
$domainRoleText = if ($domainRoleMap.ContainsKey($domainRole)) { $domainRoleMap[$domainRole] } else { 'Unknown' }
$isDomainController = $domainRole -in 4, 5

Write-Host ("Domain Controller: {0}" -f $isDomainController)
Write-Host ("Domain Role: {0}" -f $domainRoleText)
Write-Host ("Operating System: {0}" -f $os.Caption)
Write-Host ("OS Version: {0}" -f $os.Version)

Write-Host "`n=== Running Services ===" -ForegroundColor Cyan

$runningServices = Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' }

$serviceInfo = foreach ($svc in $runningServices) {
    $pathName = $svc.PathName
    $cleanPath = $null

    if ($pathName -match '^"([^\"]+)"') {
        $cleanPath = $matches[1]
    } elseif ($pathName) {
        $cleanPath = ($pathName -split '\s+')[0]
    }

    $version = 'Unknown'
    if ($cleanPath -and (Test-Path $cleanPath)) {
        $version = (Get-Item $cleanPath).VersionInfo.FileVersion
        if (-not $version) { $version = 'Unknown' }
    }

    [PSCustomObject]@{
        Name        = $svc.Name
        DisplayName = $svc.DisplayName
        State       = $svc.State
        StartMode   = $svc.StartMode
        Version     = $version
        Path        = $cleanPath
    }
}

$serviceInfo |
    Sort-Object Name |
    Format-Table -AutoSize Name, DisplayName, State, StartMode, Version
