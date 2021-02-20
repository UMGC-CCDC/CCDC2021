if ($($info -match "Windows Server 2008") -Or $($info -match "Windows 7")) { 

Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | 
    Select-Object timecreated, 
    @{Label="Account";Expression={$_.properties.value[1]}}, 
    @{Label="Commandline";Expression={$_.properties.value[8]}}, 
    @{Label="ParentProcess";Expression={$_.properties.value[13]}},
    @{Label="Win7_CmdLine";Expression={$_.properties.value[5]}} |
    Out-GridView
}
else {
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | 
    Select-Object timecreated, 
    @{Label="Account";Expression={$_.properties.value[1]}}, 
    @{Label="Commandline";Expression={$_.properties.value[8]}}, 
    @{Label="ParentProcess";Expression={$_.properties.value[13]}} |
    Out-GridView
}