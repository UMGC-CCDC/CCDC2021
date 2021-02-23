Import-Module Active Directory
$Resetpassword = Import-Csv "c:\tmp\UserList.csv"
$Password = "new_password"
 
foreach ($Account in $Resetpassword) {
    $Account.sAMAccountName
          Set-ADAccountPassword -Identity $Account.sAMAccountName -NewPassword (ConvertTo-SecureString $Password -AsPlainText -force) -Reset
}
