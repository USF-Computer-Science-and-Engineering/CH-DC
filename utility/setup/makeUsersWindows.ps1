# Define arrays of user names
$normalUsers = @(
    "lucy.nova", "xavier.blackhole", "ophelia.redding", "marcus.atlas",
    "yara.nebula", "parker.posey", "maya.star", "zachary.comet",
    "quinn.jovi", "nina.eclipse", "alice.bowie", "ruby.rose",
    "owen.mars", "bob.dylan", "samantha.stephens", "parker.jupiter",
    "carol.rivers", "taurus.tucker", "rachel.venus", "emily.waters"
)

$administratorGroup = @(
    "elara.boss", "sarah.lee", "lisa.brown", "michael.davis",
    "emily.chen", "tom.harris", "bob.johnson", "david.kim",
    "rachel.patel", "dave.grohl", "kate.skye", "leo.zenith", "jack.rover"
)

$DONOTTOUCH = @(
    "blackteam_adm"
)

# Function to create or verify a user account
function CreateOrUpdate-User {
    param (
        [string]$username,
        [string]$group = $null
    )
    if ($DONOTTOUCH -contains $username) {
        Write-Host "Skipping user $username as it's in the 'do not touch' list."
    }
    elseif (-not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
        $user = New-LocalUser -Name $username -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Password (ConvertTo-SecureString "A@StrongPassword123" -AsPlainText -Force)
        Write-Host "Created user: $username"
        if ($group) {
            Add-LocalGroupMember -Group $group -Member $username
            Write-Host "Added $username to $group group."
        }
    }
    else {
        Write-Host "User $username already exists."
    }
}

# Process normal users
foreach ($user in $normalUsers) {
    CreateOrUpdate-User -username $user
}

# Process administrator accounts
foreach ($admin in $administratorGroup) {
    CreateOrUpdate-User -username $admin -group "Administrators"
}

Write-Host "Script execution completed."