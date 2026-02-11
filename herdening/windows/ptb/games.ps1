function Install-Dependencies {
    Write-Host "Installing Python dependencies..."
    py -m pip install requests
    py -m pip install rich
}

function Create-LogDirectory {
    $logFolder = "C:\\tools\\logs"
    if (!(Test-Path -Path $logFolder)) {
        New-Item -ItemType Directory -Path $logFolder | Out-Null
        New-Item -ItemType Directory -Path C:\tools\scripts | Out-Null
        Write-Host "Created directory: $logFolder"
    } else {
        Write-Host "Directory already exists: $logFolder"
    }
}

function Enforce-GPOPolicies {
    Write-Host "Setting GPO policies..."
    auditpol /set /subcategory:"Process Creation" /success:enable

    $regPath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell"
    if (!(Test-Path -Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    $scriptBlockPath = Join-Path -Path $regPath -ChildPath "ScriptBlockLogging"
    if (!(Test-Path -Path $scriptBlockPath)) {
        New-Item -Path $scriptBlockPath -Force | Out-Null
    }

    Set-ItemProperty -Path $scriptBlockPath -Name EnableScriptBlockLogging -Value 1
    Write-Host "GPO policies applied successfully."
}

function Install-Tools {
    param (
        [string]$toolsDir = "C:\tools",
        [array]$urls = @(
            "https://download.sysinternals.com/files/ProcessMonitor.zip",
            "https://download.sysinternals.com/files/ProcessExplorer.zip",
            "https://download.sysinternals.com/files/Sysmon.zip",
            "https://download.sysinternals.com/files/TCPView.zip",
            "https://download.sysinternals.com/files/Autoruns.zip",
            "https://download.sysinternals.com/files/AdExplorer.zip",
            "https://gigenet.dl.sourceforge.net/project/systeminformer/systeminformer-3.2.25011-release-setup.exe?viasf=1",
            "https://www.nirsoft.net/utils/fileactivitywatch-x64.zip",
            "https://www.nirsoft.net/utils/folderchangesview.zip",
            "https://github.com/PowerShell/PowerShell/releases/download/v7.5.0/PowerShell-7.5.0-win-x64.msi",
            "https://github.com/ankane/pdscan/releases/download/v0.1.8/pdscan-0.1.8-x86_64-windows.zip",
            "https://ninite.com/7zip-firefox-notepadplusplus-python3-vscode/ninite.exe",
            "https://download.netlimiter.com/nl/netlimiter-5.3.26.0.exe"
        ),
        [array]$targetEXEs = @(
            "ADExplorer.exe",
            "Autoruns.exe",
            "FileActivityWatch.exe",
            "FolderChangesView.exe",
            "procexp.exe",
            "Procmon.exe",
            "tcpview.exe"
            "Sysmon.exe"
        )
    )

    $binsDir = Join-Path -Path $toolsDir -ChildPath "bins"
    $zipsDir = Join-Path -Path $toolsDir -ChildPath "zips"

 
    Add-Type -AssemblyName System.Net.Http

    function Download-File {
        param(
            [string]$url,
            [string]$outputPath
        )
    
    
        $httpClient = New-Object System.Net.Http.HttpClient
    
        try {
            $response = $httpClient.GetAsync($url).Result
            $response.EnsureSuccessStatusCode()
    
            $contentStream = $response.Content.ReadAsStreamAsync().Result
            $fileStream    = [System.IO.File]::Create($outputPath)
    
            try {
                $contentStream.CopyTo($fileStream)
            } finally {
                $fileStream.Close()
            }
            Write-Host "Downloaded: $url"
        }
        catch {
            Write-Host "Failed to download: $url"
            Write-Error $_
        }
        finally {
            $httpClient.Dispose()
        }
    }
    


    function Extract-Specific-EXEs {
        param ([string]$zipFile, [string]$destination, [array]$targetFiles)
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($zipFile)

            $extractedCount = 0
            foreach ($entry in $zip.Entries) {
                if ($targetFiles -contains $entry.Name) {
                    $outputPath = Join-Path -Path $destination -ChildPath $entry.Name
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $outputPath, $true)
                    Write-Host "Extracted: $($entry.Name) to $destination"
                    $extractedCount++
                }
            }

            if ($extractedCount -eq 0) {
                Write-Host "No target EXEs found in ZIP: $zipFile"
            }

            $zip.Dispose()
        } catch {
            Write-Host "Failed to extract from ZIP: $zipFile. Error: $_"
        }
    }


    foreach ($dir in @($toolsDir, $binsDir, $zipsDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir | Out-Null
            Write-Host "Created directory: $dir"
        }
    }


    foreach ($url in $urls) {
        $fileName = [System.IO.Path]::GetFileName($url)
        if ($fileName -eq "systeminformer-3.2.25011-release-setup.exe?viasf=1") {
            $fileName = "systeminformer-3.2.25011-release-setup.exe"  
        }

        $filePath = if ($fileName -match "\.zip$") {
            Join-Path -Path $zipsDir -ChildPath $fileName
        } else {
            Join-Path -Path $toolsDir -ChildPath $fileName
        }


        Download-File -url $url -outputPath $filePath


        if ($fileName -match "\.zip$") {
            Extract-Specific-EXEs -zipFile $filePath -destination $binsDir -targetFiles $targetEXEs
        }
    }


    $niniteInstaller = Join-Path -Path $toolsDir -ChildPath "ninite.exe"
    if (Test-Path $niniteInstaller) {
        Write-Host "Executing Ninite installer..."
        Start-Process -FilePath $niniteInstaller -Wait
        Write-Host "Ninite installation completed."
    } else {
        Write-Host "Ninite installer not found."
    }

    $sysInformerInstaller = Join-Path -Path $toolsDir -ChildPath "systeminformer-3.2.25011-release-setup.exe"
    if (Test-Path $sysInformerInstaller) {
        Write-Host "Executing SystemInformer installer..."
        Start-Process -FilePath $sysInformerInstaller -Wait
        Write-Host "SystemInformer installation completed."
    } else {
        Write-Host "SystemInformer installer not found."
    }

    $netLimiterInstaller = Join-Path -Path $toolsDir -ChildPath "netlimiter-5.3.26.0.exe"
    if (Test-Path $netLimiterInstaller) {
        Write-Host "Executing NetLimiter installer..."
        Start-Process -FilePath $netLimiterInstaller -Wait
        Write-Host "NetLimiter installation completed."
    } else {
        Write-Host "NetLimiter installer not found."
    }    

    $pwsh7 = Join-Path -Path $toolsDir -ChildPath "PowerShell-7.5.0-win-x64.msi"
    if (Test-Path $pwsh7) {
        Write-Host "installing pswh7"
        msiexec.exe /package C:\tools\PowerShell-7.5.0-win-x64.msi /quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 ADD_PATH=1
        Write-Host "pwsh7 installation completed."
    } else {
        Write-Host "pwsh7 installer not found."
    }

    Get-ChildItem -Path $toolsDir -Filter "*.exe" | ForEach-Object {
        $destination = Join-Path -Path $binsDir -ChildPath $_.Name
        Move-Item -Path $_.FullName -Destination $destination -Force
        Write-Host "Moved $($_.Name) to $binsDir"
    }

    Write-Host "All operations completed successfully."
}


function Copy-ScriptsToTools {
    param (
        [string]$destination = "C:\tools\scripts"
    )
    $source = $PSScriptRoot  
    if (!(Test-Path -Path $destination)) {
        New-Item -ItemType Directory -Path $destination | Out-Null
        Write-Host "Created directory: $destination"
    }

    Write-Host "Copying scripts from $source to $destination..."

    try {
        Copy-Item -Path "$source\*" -Destination $destination -Recurse -Force -ErrorAction Stop
        Write-Host "Successfully copied scripts to $destination"
    } catch {
        Write-Host "Failed to copy scripts: $_"
    }
}

function Main {
    Install-Tools
    Install-Dependencies
    Create-LogDirectory
    Enforce-GPOPolicies
    Copy-ScriptsToTools
    Write-Host "Setup complete with installations, directory creation, and GPO policies."
}


Main