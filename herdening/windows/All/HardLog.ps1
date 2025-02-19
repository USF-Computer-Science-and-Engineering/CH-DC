Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile 'C:\tools\SysinternalsSuite\sysmonconfig-export.xml'

Start-Process -FilePath 'C:\tools\SysinternalsSuite\sysmon.exe' -ArgumentList '/accepteula /i C:\tools\SysinternalsSuite\sysmonconfig-export.xml' -Wait

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name ScriptBlockLogging -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1
