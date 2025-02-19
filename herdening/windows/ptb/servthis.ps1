
$LogFile = "C:\tools\logs\servthis.log"


function Write-Log {
    param (
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -Append -FilePath $LogFile
}


$MonitorScriptBlock = {
    param ($ServiceNames, $LogFile)

    Function Write-Log {
        param (
            [string]$Message
        )
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$Timestamp - $Message" | Out-File -Append -FilePath $LogFile
    }

    Write-Log "Service monitoring job started."

    while ($true) {
        foreach ($ServiceName in $ServiceNames) {
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

            if ($service -and $service.Status -ne 'Running') {
                Write-Log "Service $ServiceName has stopped. Attempting to restart..."
                try {
                    Start-Service -Name $ServiceName -ErrorAction Stop
                    Start-Sleep -Seconds 5  
                    $service = Get-Service -Name $ServiceName
                    if ($service.Status -eq 'Running') {
                        Write-Log "Successfully restarted service $ServiceName."
                    } else {
                        Write-Log "Failed to restart service $ServiceName."
                    }
                } catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-Log ("Error restarting service " + $ServiceName + " - " + $ErrorMessage)
                }
            }
        }
        Start-Sleep -Seconds 3
    }
}

$RunningServices = Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -ExpandProperty Name


$Job = Start-Job -ScriptBlock $MonitorScriptBlock -ArgumentList ($RunningServices, $LogFile)

Write-Log "Monitoring job started with ID: $($Job.Id)"
Write-Output "Monitoring job started with ID: $($Job.Id)"
Write-Output "Use Get-Job to check job status and Remove-Job -Id $($Job.Id) to stop it."
