[CmdletBinding()]
param (
    [string]$dir = "C:\"
)

# Define regular expressions for detecting PII
$creditCardRegex = '\b(?:\d[ -]*?){13,16}\b'
$addressRegex = '\b\d+\s\w+\s\w+\b'
$ssnRegex = '\b\d{3}-\d{2}-\d{4}\b'
$phoneNumberRegex = '\b(?:\(\d{3}\)\s?|\d{3}[-.]?)?\d{3}[-.]?\d{4}\b'

function SearchFileForPII($filePath) {
    $fileContent = Get-Content -Raw $filePath
    $matches = @{}

    if ($fileContent -match $creditCardRegex) {
        $matches["Credit Card Numbers"] += @($fileContent -match $creditCardRegex)
    }

    if ($fileContent -match $addressRegex) {
        $matches["Addresses"] += @($fileContent -match $addressRegex)
    }

    if ($fileContent -match $ssnRegex) {
        $matches["Social Security Numbers"] += @($fileContent -match $ssnRegex)
    }

    if ($fileContent -match $phoneNumberRegex) {
        $matches["Phone Numbers"] += @($fileContent -match $phoneNumberRegex)
    }

    return $matches
}

function SearchPIIRecursively($directory) {
    $matches = @{}
    $files = Get-ChildItem -Path $directory -Recurse
    $totalCount = $files.Count
    $currentIndex = 0

    foreach ($file in $files) {
        $currentIndex++
        $percentage = [math]::Round(($currentIndex / $totalCount) * 100, 2)
        Write-Host "Progress: $percentage% - Searching file $($file.FullName)"

        if ($file.PSIsContainer) {
            $folderMatches = SearchPIIRecursively $file.FullName
            foreach ($key in $folderMatches.Keys) {
                if ($matches.ContainsKey($key)) {
                    $matches[$key] += $folderMatches[$key]
                } else {
                    $matches[$key] = $folderMatches[$key]
                }
            }
        } else {
            $fileMatches = SearchFileForPII $file.FullName
            foreach ($key in $fileMatches.Keys) {
                foreach ($match in $fileMatches[$key]) {
                    if ($match -ne $null -and $match -ne '') {
                        $matches[$key] += "Directory: $($file.FullName)`r`nMatch: $match`r`n------------------------`r`n"
                    }
                }
            }
        }
    }

    return $matches
}

$matches = SearchPIIRecursively $dir

foreach ($category in $matches.Keys) {
    Write-Host "=== $category ==="
    foreach ($match in $matches[$category]) {
        Write-Host $match
    }
}
