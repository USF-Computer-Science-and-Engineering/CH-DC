function Monitor-EventLogs {
    Write-Host "Starting Event Log Monitoring..." -ForegroundColor Green

    # Ask if the user wants to include User Login Success events
    $includeLoginEvents = Read-Host "Do you want to include User Login Success events? (Y/N)"
    $includeLoginEvents = $includeLoginEvents.Trim().ToUpper()

    # Monitor specific event IDs for Active Directory and security-related activities
    $eventFilters = @{ 
        'KerberosTicketRequested' = 4768;
        'NTLMAuthentication' = 4776;
        'SharedFolderAccess' = 5140;
        'ASRepRoasting' = 4625;
        'Kerberoasting' = 4769;
        'PotentialSAMDump' = 4662;  # Access attempt to SAM/LSA/NTDS.dit
        'PasswordChange' = 4723;
        'GroupMembershipChange' = 4728;
        'AccountLockout' = 4740;
        'ServiceAccountLogon' = 4648;
        'PrivilegedAccessAttempt' = 4673;
        'AuditPolicyChange' = 4719;
        'UserAccountCreation' = 4720;
        'UserAccountEnabled' = 4722;
        'PasswordResetAttempt' = 4724;
        'UserAccountChanged' = 4738;
        'LocalGroupMembershipChange' = 4732;
        'AuditLogCleared' = 1102;
        'ServiceInstalled' = 7045;
        'ServiceStartFailure' = 7030;
        'FirewallPacketDropped' = 2003;
        'HandleManipulation' = 4661  # Handle manipulation for SAM dump
    }

    # Add User Login Success event if the user opted in
    if ($includeLoginEvents -eq 'Y') {
        $eventFilters['UserLoginSuccess'] = 4624
    }

    # HashTable to track processed events (event ID + timestamp)
    $processedEvents = @{}

    # Array to store events for sorting by timestamp
    $eventsList = @()

    while ($true) {
        foreach ($filter in $eventFilters.GetEnumerator()) {
            $eventName = $filter.Key
            $eventID = $filter.Value

            # Retrieve events from the past 5 seconds
            $fiveSecondsAgo = (Get-Date).AddSeconds(-5)
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$eventID; StartTime=$fiveSecondsAgo} -ErrorAction SilentlyContinue

            if ($events) {
                foreach ($event in $events) {
                    # Create a unique key based on Event ID and Timestamp
                    $eventKey = "$($event.Id)-$($event.TimeCreated)"

                    # Skip the event if it has already been processed
                    if (-not $processedEvents.ContainsKey($eventKey)) {
                        $processedEvents[$eventKey] = $true

                        # Add the event to the events list for later sorting
                        $eventsList += [PSCustomObject]@{
                            EventName = $eventName
                            EventID = $event.Id
                            Timestamp = $event.TimeCreated
                            Message = $event.Message.Split("`n")[0]  # Show only the first line of the message for brevity
                            EventData = $event
                        }
                    }
                }
            }
        }

        # Sort events by timestamp (earliest to latest)
        $sortedEvents = $eventsList | Sort-Object -Property Timestamp

        # Output the sorted events
        foreach ($event in $sortedEvents) {
            Write-Host "`n[$($event.EventName)] Event Detected:" -ForegroundColor Cyan
            Write-Host "Timestamp: $($event.Timestamp)"
            Write-Host "Event ID: $($event.EventID)"
            Write-Host "Message: $($event.Message)"
            
            # Handle specific event types, such as login events
            if ($event.EventID -eq 4624 -and $includeLoginEvents -eq 'Y') {  # User Login Success (Event ID 4624)
                $username = $event.EventData.Properties[5].Value  # Account Name
                $authMethod = $event.EventData.Properties[8].Value  # Authentication Package
                Write-Host "User Login Success by $username using $authMethod" -ForegroundColor Green
            }
            elseif ($event.EventID -eq 4776) {  # NTLM Authentication (Event ID 4776)
                Write-Host "NTLM Authentication detected." -ForegroundColor Red
            }

            # Optional: Add event-specific processing if needed
            switch ($event.EventID) {
                4768 { Write-Host "Kerberos Ticket Request detected." -ForegroundColor Yellow }
                4625 { Write-Host "Possible AS-REP Roasting attempt." -ForegroundColor Yellow }
                4769 { Write-Host "Potential Kerberoasting detected." -ForegroundColor Yellow }
                4723 { Write-Host "Password Change detected." -ForegroundColor Yellow }
                4728 { Write-Host "Group Membership Change detected." }
                4740 { Write-Host "Account Lockout detected." -ForegroundColor Yellow }
                4648 { Write-Host "Service Account Logon detected." }
                4673 { Write-Host "Privileged Access Attempt detected." -ForegroundColor Red }
                4719 { Write-Host "Audit Policy Change detected." -ForegroundColor Red }
                4720 { Write-Host "User Account Creation detected." -ForegroundColor Yellow }
                4722 { Write-Host "User Account Enabled detected." -ForegroundColor Yellow }
                4724 { Write-Host "Password Reset Attempt detected." -ForegroundColor Yellow }
                4738 { Write-Host "User Account Changed detected." -ForegroundColor Yellow }
                4732 { Write-Host "Local Group Membership Change detected." }
                1102 { Write-Host "Audit Log Cleared detected." -ForegroundColor Red }
                7045 { Write-Host "New Service Installed: $($event.Properties[1].Value)" -ForegroundColor Yellow }
                7030 { Write-Host "Service Start Failure detected for $($event.Properties[0].Value)" -ForegroundColor Red }
                2003 { Write-Host "Firewall packet dropped from $($event.Properties[1].Value)" -ForegroundColor Red }
            }

            # Check for SAM/LSA/NTDS.dit dump attempts (Event ID 4662)
            if ($event.EventID -eq 4662) {
                # Check for access to SAM/LSA/NTDS.dit files or registry
                if ($event.Message -match "SAM" -or $event.Message -match "LSA" -or $event.Message -match "NTDS.dit") {
                    Write-Host "Potential SAM/LSA/NTDS.dit dump attempt detected." -ForegroundColor Red
                    Write-Host "Details: $($event.Message)"
                }
            }

            # Check for Handle Manipulation (Event ID 4661)
            if ($event.EventID -eq 4661) {
                # Check if the handle access request is related to SAM/LSA
                if ($event.Message -match "SAM" -or $event.Message -match "LSA") {
                    Write-Host "Possible SAM/LSA Handle Manipulation detected." -ForegroundColor Red
                    Write-Host "Details: $($event.Message)"
                }
            }
        }

        # Clear the events list for the next cycle
        $eventsList.Clear()

        # Sleep for 5 seconds before checking again
        Start-Sleep -Seconds 5
    }
}

# Run the monitoring directly instead of launching a new process
Monitor-EventLogs
