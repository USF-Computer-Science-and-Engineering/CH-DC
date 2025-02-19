$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch  # start a timer to measure scan time
$stopWatch.Start()

# define patterns for pii detection with labels
# these are simple regex patterns to catch common pii formats
$piiPatterns = @(
    @{ Label = "SSN FOUND"; Pattern = "\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b" },  # social security numbers
    @{ Label = "Credit Card FOUND"; Pattern = "\b\d{13,16}\b" },              # credit card numbers (basic, may catch random long numbers)
    @{ Label = "Phone Number FOUND"; Pattern = "\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b" },  # phone numbers
    @{ Label = "Address FOUND"; Pattern = "\b\d{1,5}\s\w+(\s\w+)*\s(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Court|Ct|Lane|Ln|Way|Highway|Hwy)\b" }, # addresses
    @{ Label = "Email FOUND"; Pattern = "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b" } # emails
)

# $scanPaths = @("C:\Users", "C:\inetpub", "D:\", "C:\ProgramData")
$scanPaths = @("C:\Users\")

Write-Host "`nScanning Directory: $scanPaths" -ForegroundColor Cyan  # tell user where we're looking

# store results
$foundPII = @{}  # dictionary to store found pii
$logFile = "C:\tools\logs\PII_Scan_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"  # log file name with timestamp

Write-Host "`nScanning for PII... (this may take time)" -ForegroundColor Magenta  # warn user


# scan all files in the selected directory
foreach ($path in $scanPaths) {
    try {
        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' -and $_.FullName -notmatch 'AppData' -and $_.FullName -notmatch 'CH-DC' } | ForEach-Object {
            $filePath = $_.FullName
            $content = Get-Content -Path $filePath -Raw -ErrorAction SilentlyContinue  # read the entire file at once
            
            # check each pii pattern
            foreach ($pii in $piiPatterns) {
                if ($content -match $pii.Pattern) {
                    $matches = [regex]::Matches($content, $pii.Pattern) | Select-Object -ExpandProperty Value
                    
                    # store results, avoiding duplicates
                    foreach ($match in $matches) {
                        $formattedMatch = "$($pii.Label): $match"
                        if (!$foundPII.ContainsKey($filePath)) {
                            $foundPII[$filePath] = @()
                        }
                        $foundPII[$filePath] += $formattedMatch
                    }
                }
            }
        }
    } catch {
        Write-Host "Error accessing: $path" -ForegroundColor Red  # handle file access errors
    }
    Write-Host "$path - Completed" -ForegroundColor Green  # let user know we're done with this directory
}

# output results
if ($foundPII.Count -gt 0) {
    Write-Host "`nPII Found in $($foundPII.Count) files!" -ForegroundColor Green
    $foundPII.GetEnumerator() | ForEach-Object {
        Write-Host "`nFile: $($_.Key)" -ForegroundColor Yellow
        $_.Value | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }

    # save results to log file
    $foundPII.GetEnumerator() | ForEach-Object {
        Add-Content -Path $logFile -Value "`nFile: $($_.Key)"
        $_.Value | ForEach-Object { Add-Content -Path $logFile -Value "  - $_" }
    }

    Write-Host "`nResults saved to: $logFile" -ForegroundColor Cyan
} else {
    Write-Host "`nNo PII Detected." -ForegroundColor Red
}

# end timer
$stopWatch.Stop()
Write-Host "`nScan Completed in $($stopWatch.Elapsed.TotalSeconds) seconds." -ForegroundColor Cyan
