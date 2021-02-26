$info = systeminfo | findstr /B /C:"OS Name" /B /C:"OS Version"

# Selectively check the logging

Write-Output "## Check audit logging status"
$check = AUDITPOL /GET /SUBCATEGORY:"Process Creation"
$check2 = AUDITPOL /GET /SUBCATEGORY:"Logon"
if ($($check -match "Success and Failure") -and $($check2 -match "Success and Failure")) {
    Write-Output "Audit Logging is set"
}
else {
    Write-Output "!Audit Logging Unset!"
}

# Enable all the logging 

wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl "Windows Powershell" /ms:1024000

AUDITPOL /SET /SUBCATEGORY:"Process Creation" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Logon" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Logoff" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Other Logon/Logoff Events" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Other Object Access Events" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"User Account Management" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Security Group Management" /SUCCESS:enable /FAILURE:enable
AUDITPOL /SET /SUBCATEGORY:"Security System Extension" /SUCCESS:enable /FAILURE:enable

# Check the firewall status

Write-Output "## Firewall Status"
Netsh Advfirewall show allprofiles | findstr -i "Settings State"

# Enable firewall automatically
NetSh Advfirewall set allprofiles state on

# Check the most recent firewall rule for new additions
Write-Output "## Most recent firewall rule"
netsh advfirewall firewall show rule name=all | select -First 15

# Check for recently created users
$time =  ((Get-Date).AddSeconds(-10))
$filename = Get-Date -Format yyyy.MM.dd
$exportcsv="c:\tmp\ad_users_creators" + $filename + ".csv"
Get-WinEvent -FilterHashtable @{LogName="Security";ID=4720;StartTime=$Time}| Foreach {
$event = [xml]$_.ToXml()
if($event)
{
$Time = Get-Date $_.TimeCreated -UFormat "%Y-%m-%d %H:%M:%S"
$CreatorUser = $event.Event.EventData.Data[4]."#text"
$NewUser = $event.Event.EventData.Data[0]."#text"
$comp = $event.Event.System.computer
$dc + "|" + $Time + "|" + $NewUser + "|" + $CreatorUser| out-file $exportcsv -append
}
}

# Last 5 login events
Write-Output "## Last 5 login events"
Get-WinEvent -MaxEvents 5 -FilterHashtable @{logname='security';id='4624'} |
    select timecreated, 
    @{Label="Account Name";Expression={$_.properties.value[5]}}, 
    @{Label="LogonType";Expression={$_.properties.value[8]}}, 
    @{Label="Process Name";Expression={$_.properties.value[17]}}

# Last 150 processes that match certain indicators

if ($($info -match "Windows Server 2008") -Or $($info -match "Windows 7")) { 

Get-WinEvent -MaxEvents 50 -FilterHashtable @{logname='security';id='4688'} | 
    Select-Object timecreated, 
    @{Label="Account";Expression={$_.properties.value[1]}}, 
    @{Label="Commandline";Expression={$_.properties.value[8]}}, 
    @{Label="ParentProcess";Expression={$_.properties.value[13]}},
    @{Label="Win7_CmdLine";Expression={$_.properties.value[5]}} | findstr /i "TimeCreated cmd powershell wmic net.exe net1.exe netsh sc.exe schtasks wscript cscript dllhost regsvr32 certutil rundll rundll32 wmic http wevtutil" #| Out-GridView
}
elseif ($($info -match "Windows Server 2012") -Or $($info -match "Windows 8")) {
Get-WinEvent -MaxEvents 200 -FilterHashtable @{logname='security';id='4688'} | 
    Select-Object timecreated, 
    @{Label="Account";Expression={$_.properties.value[1]}}, 
    @{Label="Commandline";Expression={$_.properties.value[5]}} | findstr /i "TimeCreated cmd powershell wmic net.exe net1.exe netsh sc.exe schtasks wscript cscript dllhost regsvr32 certutil rundll rundll32 wmic http wevtutil" #| Out-Gridview
}
else {
Get-WinEvent -MaxEvents 200 -FilterHashtable @{logname='security';id='4688'} | 
    Select-Object timecreated, 
    @{Label="Account";Expression={$_.properties.value[1]}}, 
    @{Label="Commandline";Expression={$_.properties.value[8]}}, 
    @{Label="ParentProcess";Expression={$_.properties.value[13]}} | findstr /i "TimeCreated cmd powershell wmic net.exe net1.exe netsh sc.exe schtasks wscript cscript dllhost regsvr32 certutil rundll rundll32 wmic http wevtutil" #| Out-Gridview
}

# Netstat

netstat -anob | findstr ESTABLISHED
