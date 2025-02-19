New-NetFirewallRule -DisplayName "Allow DNS" -Direction Inbound -Protocol TCP -LocalPort 53
New-NetFirewallRule -DisplayName "Allow DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53
New-NetFirewallRule -DisplayName "Allow Kerberos" -Direction Inbound -Protocol TCP -LocalPort 88
New-NetFirewallRule -DisplayName "Allow Kerberos UDP" -Direction Inbound -Protocol UDP -LocalPort 88
New-NetFirewallRule -DisplayName "Allow W32Time" -Direction Inbound -Protocol UDP -LocalPort 123
New-NetFirewallRule -DisplayName "Allow RPC Endpoint Mapper" -Direction Inbound -Protocol TCP -LocalPort 135
New-NetFirewallRule -DisplayName "Allow NetBIOS" -Direction Inbound -Protocol UDP -LocalPort 137,138
New-NetFirewallRule -DisplayName "Allow NetBIOS" -Direction Inbound -Protocol TCP -LocalPort 139
New-NetFirewallRule -DisplayName "Allow LDAP" -Direction Inbound -Protocol TCP -LocalPort 389
New-NetFirewallRule -DisplayName "Allow LDAP UDP" -Direction Inbound -Protocol UDP -LocalPort 389
New-NetFirewallRule -DisplayName "Allow SMB" -Direction Inbound -Protocol TCP -LocalPort 445
New-NetFirewallRule -DisplayName "Allow Kerberos password change" -Direction Inbound -Protocol TCP -LocalPort 464
New-NetFirewallRule -DisplayName "Allow Kerberos password change UDP" -Direction Inbound -Protocol UDP -LocalPort 464
New-NetFirewallRule -DisplayName "Allow LDAP SSL" -Direction Inbound -Protocol TCP -LocalPort 636
New-NetFirewallRule -DisplayName "Allow LDAP Global Catalog" -Direction Inbound -Protocol TCP -LocalPort 3268
New-NetFirewallRule -DisplayName "Allow LDAP GC SSL" -Direction Inbound -Protocol TCP -LocalPort 3269
New-NetFirewallRule -DisplayName "Allow RPC Ephemeral Ports" -Direction Inbound -Protocol TCP -LocalPort 49152-65535
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Protocol TCP -LocalPort 22
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389
	
Get-NetFirewallRule | Where-Object {$_.DisplayName -notlike "Allow DNS" -and $_.DisplayName -notlike "Allow DNS UDP" -and $_.DisplayName -notlike "Allow Kerberos" -and $_.DisplayName -notlike "Allow Kerberos UDP" -and $_.DisplayName -notlike "Allow W32Time" -and $_.DisplayName -notlike "Allow RPC Endpoint Mapper" -and $_.DisplayName -notlike "Allow NetBIOS" -and $_.DisplayName -notlike "Allow NetBIOS" -and $_.DisplayName -notlike "Allow LDAP" -and $_.DisplayName -notlike "Allow LDAP UDP" -and $_.DisplayName -notlike "Allow SMB" -and $_.DisplayName -notlike "Allow Kerberos password change" -and $_.DisplayName -notlike "Allow Kerberos password change UDP" -and $_.DisplayName -notlike "Allow LDAP SSL" -and $_.DisplayName -notlike "Allow LDAP Global Catalog" -and $_.DisplayName -notlike "Allow LDAP GC SSL" -and $_.DisplayName -notlike "Allow RPC Ephemeral Ports" -and $_.DisplayName -notlike "Allow SSH" -and $_.DisplayName -notlike "Allow RDP"} | Remove-NetFirewallRule