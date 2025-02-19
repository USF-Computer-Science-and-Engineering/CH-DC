New-Item -ItemType Directory -Path 'C:\tools\' -Force

$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SysinternalsSuite.zip' -OutFile 'C:\tools\SysinternalsSuite.zip'

Expand-Archive -Path 'C:\tools\SysinternalsSuite.zip' -DestinationPath 'C:\tools\SysinternalsSuite' -Force

Remove-Item 'C:\tools\SysinternalsSuite.zip'

Start-Process -FilePath 'C:\tools\SysinternalsSuite\procexp64.exe'

Start-Process -FilePath 'C:\tools\SysinternalsSuite\tcpview64.exe'
