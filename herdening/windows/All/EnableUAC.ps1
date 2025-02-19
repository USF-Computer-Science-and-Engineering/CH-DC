
param(
    [string]$action = "apply" 
)

function Enable-UAC {
    Write-Host "Enabling UAC using Registry..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
        Write-Host "UAC enabled successfully using Registry."
    } catch {
        Write-Host "Failed to enable UAC using Registry. Attempting alternative method..."
        Enable-UAC-GUI
    }
}

function Enable-UAC-GUI {
    Write-Host "Enabling UAC using GUI..."
    Show-ControlPanelItem "Microsoft.UserAccounts"
    Write-Host "UAC enabled successfully using GUI."
}

function Disable-UAC {
    Write-Host "Disabling UAC using Registry..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
        Write-Host "UAC disabled successfully using Registry."
    } catch {
        Write-Host "Failed to disable UAC using Registry. Attempting alternative method..."
        Disable-UAC-GUI
    }
}

function Disable-UAC-GUI {
    Write-Host "Disabling UAC using GUI..."
    Show-ControlPanelItem "Microsoft.UserAccounts\TasksAndFeatures"
    Write-Host "UAC disabled successfully using GUI."
}

function Show-ControlPanelItem {
    param(
        [string]$controlPanelItem
    )

    $controlPanel = New-Object -ComObject Shell.Application
    $controlPanel.Namespace('::{26EE0668-A00A-44D7-9371-BEB064C98683}\0\::' + $controlPanelItem).InvokeVerb('Properties')
}

if ($action -eq "apply") {
    Enable-UAC
} elseif ($action -eq "revert") {
    Disable-UAC
} else {
    Write-Host "Invalid action. Please use 'apply' or 'revert'."
}
