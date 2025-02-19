

Get-Service -Name Spooler | Stop-Service -Force
Set-Service -Name Spooler -StartupType Disabled -Status Stopped

dism /online /disable-feature /featurename:TelnetClient /NoRestart

Get-Service -Name WinRM | Stop-Service -Force
Set-Service -Name WinRM -StartupType Disabled -Status Stopped -Confirm $false

# Require interactie logon for true admin connections (RDP, SSH, etc.)
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system -Name LocalAccountTokenFilterPolicy -Value 0

# Remove sticky keys
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
TAKEOWN /F C:\Windows\System32\sethc.exe /A
ICACLS C:\Windows\System32\sethc.exe /grant administrators:F
del C:\Windows\System32\sethc.exe -Force

# Remove all custom password filters
REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages"  /f

# Remove sticky keys
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
TAKEOWN /F C:\Windows\System32\sethc.exe /A
ICACLS C:\Windows\System32\sethc.exe /grant administrators:F
del C:\Windows\System32\sethc.exe -Force

# Delete utility manager 
TAKEOWN /F C:\Windows\System32\Utilman.exe /A
ICACLS C:\Windows\System32\Utilman.exe /grant administrators:F
del C:\Windows\System32\Utilman.exe -Force

# Delete on screen keyboard 
TAKEOWN /F C:\Windows\System32\osk.exe /A
ICACLS C:\Windows\System32\osk.exe /grant administrators:F
del C:\Windows\System32\osk.exe -Force

# Delete narrator 
TAKEOWN /F C:\Windows\System32\Narrator.exe /A
ICACLS C:\Windows\System32\Narrator.exe /grant administrators:F
del C:\Windows\System32\Narrator.exe -Force

# Delete magnify
TAKEOWN /F C:\Windows\System32\Magnify.exe /A
ICACLS C:\Windows\System32\Magnify.exe /grant administrators:F
del C:\Windows\System32\Magnify.exe -Force

# Set Data Execution Prevention (DEP) to be always on
bcdedit.exe /set "{current}" nx AlwaysOn

 #Only privileged groups can add or delete printer drivers
 reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f


#Don't allow empty password login
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f


#Enable UAC popups if software trys to make changes
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

#Require admin authentication for operations that requires elevation of privileges
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorAdmin /T REG_DWORD /D 1 /F
# Does not allow user to run elevates privileges
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorUser /T REG_DWORD /D 0 /F

# Mitigate LLMNR Poisoning
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD -Force


Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile 'C:\tools\sysconf.xml'

Start-Process -FilePath 'C:\tools\bins\Sysmon.exe' -ArgumentList '/accepteula /i C:\tools\sysconf.xml' -Wait

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name ScriptBlockLogging -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1