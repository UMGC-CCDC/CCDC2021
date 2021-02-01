## Try to wget important stuff

#Start-Process -FilePath powershell.exe -ArgumentList "-noni -windowstyle hidden -command Invoke-WebRequest https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile ./SysinternalSuite.zip";
#Start-Process -FilePath powershell.exe -ArgumentList "-noni -windowstyle hidden -command https://github.com/ION28/BLUESPAWN/releases/download/v0.5.0-alpha/BLUESPAWN-client-x64.exe -OutFile ./BLUESPAWN-client-x64.exe";

## Disable adapters to cut internet connection

# have to dip into wmic, older Get-NetAdapter is too new
wmic path win32_networkadapter where PhysicalAdapter=True call disable

## Change passwords
$newSecurePassword = ConvertTo-SecureString "you should change this P@ssw0rd" -AsPlainText -Force
ForEach ($user in (Get-ADGroupMember "Domain Admins").name) {
Set-ADAccountPassword -Identity "$user" -NewPassword $newSecurePassword -Reset
}
