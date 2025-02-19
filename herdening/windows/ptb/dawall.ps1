# Ensure RDP and SSH stay open and unblockable
Write-Host "Ensuring RDP and SSH remain open..."
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -Enabled True -PolicyStore PersistentStore -Group "RemoteDesktop"
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -Enabled True -PolicyStore PersistentStore -Group "SSH"

# Function to check and start a service if not already running
function Ensure-ServiceRunning {
    param (
        [string]$ServiceName
    )
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Running') {
        Write-Host "Starting $ServiceName..."
        Set-Service -Name $ServiceName -StartupType Automatic
        Start-Service -Name $ServiceName
    } else {
        Write-Host "$ServiceName is already running."
    }
}

# Prevent accidental blocking of RDP and SSH
$rdpRule = Get-NetFirewallRule -DisplayName "Allow RDP" -ErrorAction SilentlyContinue
if ($rdpRule) {
    Set-NetFirewallRule -DisplayName "Allow RDP" -Action Allow -Enabled True -Direction Inbound
}

$sshRule = Get-NetFirewallRule -DisplayName "Allow SSH" -ErrorAction SilentlyContinue
if ($sshRule) {
    Set-NetFirewallRule -DisplayName "Allow SSH" -Action Allow -Enabled True -Direction Inbound
}

# Prompt to confirm if the script is running on a workstation or a Domain Controller
$computerRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
if ($computerRole -ge 4) {
    $isDC = $true
    Write-Host "Detected Domain Controller (DC)."
} else {
    $isDC = $false
    Write-Host "Detected Workstation."
}

# List of required services for a workstation connected to a Domain Controller
$wsRequiredServices = @("Workstation", "LanmanWorkstation", "DNSCache", "NlaSvc", "Netlogon", "W32Time", "AarSvc", "AJRouter", "ALG", "AppIDSvc", "Appinfo", "AppMgmt", "AppReadiness", "AppXSvc", "AssignedAccessManagerSvc", "AudioEndpointBuilder", "Audiosrv", "AxInstSV", "BDESVC", "BFE", "BITS", "BluetoothUserService", "BrokerInfrastructure", "Browser", "BthAvctpSvc", "BthHFSrv", "cbdhsvc", "CDPSvc", "CDPUserSvc", "CertPropSvc", "ClipSVC", "CNGKeyIsolation", "COMSysApp", "CoreMessagingRegistrar", "CryptSvc", "DcomLaunch", "defragsvc", "DeviceAssociationService", "DeviceInstall", "DevicePickerUserSvc", "DevicesFlowUserSvc", "DevQueryBroker", "Dhcp", "diagnosticshub.standardcollector.service", "DiagTrack", "DispBrokerDesktopSvc", "DisplayEnhancementService", "DMSVC", "Dnscache", "DoSvc", "dot3svc", "DPS", "DsSvc", "DusmSvc", "Eaphost", "EFS", "embeddedmode", "EntAppSvc", "EventLog", "EventSystem", "Fax", "fdPHost", "FDResPub", "fhsvc", "FontCache", "FrameServer", "GraphicsPerfSvc", "hidserv", "HvHost", "icssvc", "IKEEXT", "InstallService", "iphlpsvc", "IpxlatCfgSvc", "KeyIso", "KtmRm", "LanmanServer", "LanmanWorkstation", "lfsvc", "LicenseManager", "lltdsvc", "lmhosts", "LxssManager", "mpssvc", "MSiSCSI", "MSDTC", "MSMQ", "MSMQTriggers", "NaturalAuthentication", "NcaSvc", "NcbService", "NcdAutoSetup", "Netlogon", "Netman", "netprofm", "NetSetupSvc", "NetTcpPortSharing", "NgcCtnrSvc", "NgcSvc", "NlaSvc", "nsi", "OneSyncSvc", "P9RdrService", "p2pimsvc", "p2psvc", "PcaSvc", "PeerDistSvc", "PerfHost", "PhoneSvc", "PimIndexMaintenanceSvc", "pla", "PlugPlay", "PNRPAutoReg", "PNRPsvc", "PolicyAgent", "Power", "PrintNotify", "ProfSvc", "PushToInstall", "QWAVE", "RasAuto", "RasMan", "RemoteAccess", "RemoteRegistry", "RetailDemo", "RpcEptMapper", "RpcLocator", "RpcSs", "SamSs", "SCardSvr", "ScDeviceEnum", "Schedule", "SCPolicySvc", "SDRSVC", "seclogon", "SENS", "SensorDataService", "SensorService", "SensrSvc", "SessionEnv", "SgrmBroker", "SharedAccess", "SharedRealitySvc", "ShellHWDetection", "shpamsvc", "smphost", "SmsRouter", "SNMPTRAP", "spectrum", "Spooler", "sppsvc", "SSDPSRV", "ssh-agent", "StateRepository", "stisvc", "StorSvc", "svsvc", "swprv", "SysMain", "SystemEventsBroker", "TabletInputService", "TapiSrv", "TermService", "Themes", "TieringEngineService", "TimeBrokerSvc", "TrkWks", "TrustedInstaller", "UdkUserSvc", "UevAgentService", "UmRdpService", "upnphost", "UserManager", "UsoSvc", "VacSvc", "VaultSvc", "vds", "vmicguestinterface", "vmicheartbeat", "vmickvpexchange", "vmicrdv", "vmicshutdown", "vmictimesync", "vmicvmsession", "vmicvss", "VSS", "W32Time", "WalletService", "WarpJITSvc", "WbioSrvc", "Wcmsvc", "wcncsvc", "WdiServiceHost", "WdiSystemHost", "WdsSvc", "WebClient", "Wecsvc", "WEPHOSTSVC", "wercplsupport", "WerSvc", "WFDSConMgrSvc", "wifimansvc", "WinDefend", "WindowsBiometricService", "WindowsInsiderService", "WinHttpAutoProxySvc", "Winmgmt", "WinRM", "WlanSvc", "wlidsvc", "wlpasvc", "wmiApSrv", "WMPNetworkSvc", "workfolderssvc", "WpcMonSvc", "WpnService", "WpnUserService", "wscsvc", "WSearch", "wuauserv", "WudfSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc")

# List of required services for a Domain Controller
$dcRequiredServices = @("NTDS", "DNS", "DHCPServer", "W32Time", "Netlogon", "kdc", "DFS", "AppHostSvc", "AppXSvc", "NgcCtnrSvc", "RemoteRegistry", "wmiApSrv", "WPDBusEnum", "BalloonService", "BFE", "BITS", "BrokerInfrastructure", "CDPSvc", "BDPUserSvc_7877c", "CertPropSvc", "ClipSVC", "CoreMessagingRegistrar", "CryptSvc", "DcomLaunch", "Dfs", "Dhcp", "DiagTrack", "Dnscache", "DoSvc", "EFS", "ADWS", "BDPUserSvc_7877c", "EventSystem", "FontCache", "IAS", "IISAdmin", "IsmServ", "KeyIso", "KPSSVC", "LSM", "MSDTC", "msiserver", "NcbService", "netprofm", "NlaSvc", "nsi", "PcaSvc", "PlugPlay", "Power", "ProfSvc", "RpcEptMapper", "RPCHTTPLBS", "sacsvr", "SENS", "SessionEnv", "ShellHWDetection", "StateRepository", "SysMain", "SystemEventsBroker", "TabletInputService", "Themes", "TimeBrokerSvc", "TokenBroker", "TSGateway", "UALSVC", "UmRdpService", "UserManager", "UsoSvc", "vds", "W3SVC", "WAS", "Wcmsvc", "WdNisSvc", "WinDefend", "WpnService", "WpnUserService_7877c", "wuauserv", "DFSR", "CDPUserSvc_96de0", "EventLog", "gpsvc", "IKEEXT", "iphlpsvc", "LanmanServer", "LanmanWorkstation", "lmhosts", "mpssvc", "PolicyAgent", "RpcSs", "SamSs", "Schedule", "Spooler", "StorSvc", "TermService", "Winmgmt", "WpnUserService_96de0")

# Function to get default firewall rules
function Get-DefaultFirewallRules {
    Write-Host "Retrieving default firewall rules..."
    $defaultRules = Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Profile
    return $defaultRules
}

# Function to get current firewall rules
function Get-CurrentFirewallRules {
    Write-Host "Retrieving current firewall rules..."
    $currentRules = Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Profile
    return $currentRules
}

# Compare current firewall rules with defaults
function Compare-FirewallRules {
    Write-Host "Comparing current firewall rules with defaults..."
    $defaultRules = Get-DefaultFirewallRules
    $currentRules = Get-CurrentFirewallRules
    $differences = Compare-Object -ReferenceObject $defaultRules -DifferenceObject $currentRules -Property DisplayName, Direction, Action, Profile
    return $differences
}

# Detect running services and suggest allow rules
function Suggest-AllowRules {
    Write-Host "Detecting running services..."
    $services = Get-Service | Where-Object { $_.Status -eq 'Running' }
    
    foreach ($service in $services) {
        $serviceName = $service.Name
        
        if ($isDC -and $dcRequiredServices -contains $serviceName) {
            Write-Host "Automatically allowing required DC service: $serviceName"
            New-NetFirewallRule -DisplayName "Allow_$serviceName" -Direction Inbound -Action Allow -Enabled True -Service $serviceName | Out-Null
            continue
        }
		
		if (-not $isDC -and $wsRequiredServices -contains $serviceName) {
            Write-Host "Automatically allowing required workstation service: $serviceName"
            New-NetFirewallRule -DisplayName "Allow_$serviceName" -Direction Inbound -Action Allow -Enabled True -Service $serviceName | Out-Null
            continue
        }
        
        
        Write-Host "Suggest allowing: $serviceName (Y/N)?" -NoNewline
        $input = Read-Host
        if ($input -eq 'Y') {
            New-NetFirewallRule -DisplayName "Allow_$serviceName" -Direction Inbound -Action Allow -Enabled True -Service $serviceName
        }
    }
    
    # Ask if specific ports should be allowed for inbound and outbound connections
    Write-Host "Would you like to allow specific ports? Enter a comma-separated list or press Enter to skip: " -NoNewline
    $ports = Read-Host
    if ($ports -match "\d") {
        $portList = $ports -split "," | ForEach-Object { $_.Trim() }
        foreach ($port in $portList) {
            Write-Host "Allow inbound connections on port $port? (Y/N)" -NoNewline
            $allowInbound = Read-Host
            if ($allowInbound -eq 'Y') {
                New-NetFirewallRule -DisplayName "Allow Inbound Port $port" -Direction Inbound -Action Allow -LocalPort $port -Protocol TCP
            }
            Write-Host "Allow outbound connections on port $port? (Y/N)" -NoNewline
            $allowOutbound = Read-Host
            if ($allowOutbound -eq 'Y') {
                New-NetFirewallRule -DisplayName "Allow Outbound Port $port" -Direction Outbound -Action Allow -LocalPort $port -Protocol TCP
            }
        }
    }
}

# Helper functions for firewall rule normalization
function CanonicalizeField {
    param ([string]$s)
    if ($null -eq $s) { return "" }
    return $s.Trim().ToLower()
}

function CanonicalizePort {
    param ([string]$port)
    if ($null -eq $port) { return "" }
    return ($port.ToLower() -replace '[\s,]','')
}

function Normalize-ProtocolValue {
    param ([string]$protocol)
    return CanonicalizeField $protocol
}

# Add implicit deny rule excluding RDP and SSH
function Add-ImplicitDeny {
    Write-Host "Adding implicit deny rule for all other traffic except RDP and SSH..."
    New-NetFirewallRule -DisplayName "Implicit Deny" -Direction Inbound -Action Block -Enabled True -Protocol TCP -LocalPort 1-21,23-3388,3390-65535
}

# Ensure log directory exists
$logPath = "C:\Tools\Logs\Firewall.log"
$logDir = [System.IO.Path]::GetDirectoryName($logPath)
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Monitor firewall for changes and log to file
function Monitor-FirewallChanges {
    Write-Host "Monitoring firewall for changes..."
    $query = "SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA 'MSFT_NetFirewallRule'"
    $watcher = New-Object Management.EventQuery($query)
    $scope = New-Object Management.ManagementScope("\\.\root\StandardCimv2")
    $watcherObject = New-Object Management.ManagementEventWatcher($scope, $watcher)

    while ($true) {
        $event = $watcherObject.WaitForNextEvent()
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "$timestamp - Firewall rule changed: $($event.TargetInstance.DisplayName)"
        
        # Log to file
        Add-Content -Path $logPath -Value $logEntry

        # Optional: Also print to console
        Write-Host $logEntry
    }
}

# Enable RDP in registry
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

# Enable SSH in registry (if applicable, mostly needed for OpenSSH on Windows)
Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue

# Ensure RDP and SSH services are running
Ensure-ServiceRunning -ServiceName "TermService"
Ensure-ServiceRunning -ServiceName "sshd"

# Allow RDP through Windows Firewall
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -EdgeTraversalPolicy Allow -ErrorAction SilentlyContinue
Set-NetFirewallRule -Group "Remote Desktop" -Enabled True -Profile Any -ErrorAction SilentlyContinue

# Allow SSH through Windows Firewall
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -ErrorAction SilentlyContinue

Suggest-AllowRules
Add-ImplicitDeny

#Add malware bytes binaries to firewall
# Define the target directory
$targetDir = "C:\Program Files\Malwarebytes\Anti-Malware\"


$exeFiles = Get-ChildItem -Path $targetDir -Filter "*.exe" -File


foreach ($exe in $exeFiles) {
    $ruleName = "Block Outbound - " + $exe.Name
    $exePath = $exe.FullName


    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

    if (-not $existingRule) {
        Write-Host "Creating firewall rule for: $exePath"

        New-NetFirewallRule -DisplayName $ruleName `
                            -Direction Outbound `
                            -Action Block `
                            -Program $exePath `
                            -Profile Any `
                            -Enabled True
    } else {
        Write-Host "Firewall rule already exists for: $exePath"
    }
}

Write-Host "All applicable outbound rules have been created."



Monitor-FirewallChanges
