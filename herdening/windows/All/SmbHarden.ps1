# SMB Hardening

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Enable SMB Signing
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# Disable anonymous login
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -Value 1

# Enforce NTLMv2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

# Disable NetBIOS over TCP/IP
$base = "HKLM:SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"

$interfaces = Get-ChildItem $base | Select -ExpandProperty PSChildName

# To revert change, run this and set value to 0
foreach($interface in $interfaces) {
    Set-ItemProperty -Path "$base\$interface" -Name "NetbiosOptions" -Value 2
}
