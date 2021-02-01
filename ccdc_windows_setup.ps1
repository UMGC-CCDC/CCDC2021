$newSecurePassword = ConvertTo-SecureString "you should change this P@ssw0rd" -AsPlainText -Force
ForEach ($user in (Get-ADGroupMember "Domain Admins").name) {
Set-ADAccountPassword -Identity "$user" -NewPassword $newSecurePassword -Reset
}
