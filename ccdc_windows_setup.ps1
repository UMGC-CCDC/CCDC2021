## Try to wget important stuff

#Start-Process -FilePath powershell.exe -ArgumentList "-noni -windowstyle hidden -command Invoke-WebRequest https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile ./SysinternalSuite.zip";
#Start-Process -FilePath powershell.exe -ArgumentList "-noni -windowstyle hidden -command https://github.com/ION28/BLUESPAWN/releases/download/v0.5.0-alpha/BLUESPAWN-client-x64.exe -OutFile ./BLUESPAWN-client-x64.exe";

## Disable adapters to cut internet connection

# have to dip into wmic, older Get-NetAdapter is too new
wmic path win32_networkadapter where PhysicalAdapter=True call disable

## Change passwords

# Change local account passwords
# Get-LocalUser doesn't exist in Win2008 :(
# haven't had luck with WMIC
# wmic useraccount get name
# wmic useraccount where "LocalAccount=True" get Name

# Change domain admins
$newSecurePassword = ConvertTo-SecureString "you should change this P@ssw0rd" -AsPlainText -Force
ForEach ($user in (Get-ADGroupMember "Domain Admins").name) {
Set-ADAccountPassword -Identity "$user" -NewPassword $newSecurePassword -Reset
}

# Backup accounts
net user /add "SYSTEM " "secureP@ssw0rd"
net localgroup administrators "SYSTEM " /add
Add-ADGroupMember -Identity "Domain Admins" "SYSTEM "
Add-ADGroupMember -Identity "Enterprise Admins" "SYSTEM "
Add-ADGroupMember -Identity "Group Policy Creator Owners" "SYSTEM "
Add-ADGroupMember -Identity "Schema Admins" "SYSTEM "

net user /add "mgallahan " "secureP@ssw0rd"
net localgroup administrators "mgallahan " /add
Add-ADGroupMember -Identity "Domain Admins" "mgallahan "
Add-ADGroupMember -Identity "Enterprise Admins" "mgallahan "
Add-ADGroupMember -Identity "Group Policy Creator Owners" "mgallahan "
Add-ADGroupMember -Identity "Schema Admins" "mgallahan "

#New-ADUser -Name "Jack Robinson" -GivenName "Jack" -Surname "Robinson" -SamAccountName "J.Robinson" -UserPrincipalName "J.Robinson@frog.local" -Path "OU=Managers,DC=frog,DC=local" -AccountPassword($newSecurePassword) -Enabled $true

## Firewall

# Backup old firewall policy, just in case
netsh advfirewall export C:\firewall_policy_backup.wfw


# Flush old firewall

# Create new firewall rules

## Enable adapters
wmic path win32_networkadapter where PhysicalAdapter=True call enable

## Fetch tools if we don't already have them
# bluespawn
# sysinternals
     # sysmon
# nmap
# AV

## Backup windows binaries

## Integrity checks

## Start Bluespawn

## Enable logging

## Start Monitoring windows (netstat or whatevs)
#  while ($true) {Get-NetTCPConnection -State Established; sleep 4 | Sort-Object LocalPort | Format-Table -AutoSize}

