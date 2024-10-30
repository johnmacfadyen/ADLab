$baseDN = "DC=lab,DC=gobrr,DC=dev"
$orgName = "GoBrr Health"

$baseOU = "OU=$orgName,$baseDN"

# Remove AD role groups from the groups OU
get-adgroup -SearchBase $baseOU -filter * |  Set-ADObject -ProtectedFromAccidentalDeletion:$false -PassThru | Remove-ADGroup -Confirm:$false

# Get all the users in the base OU and remove them
Get-ADUser -SearchBase $baseOU -Filter * | Set-ADObject -ProtectedFromAccidentalDeletion:$false -PassThru | Remove-ADUser -Confirm:$false

# Remove OUs from the base OU in reverse order
$subtree = Get-ADOrganizationalUnit -SearchBase $baseOU -Filter * -SearchScope Subtree
$subtree[($subtree.Length)..0] | ForEach-Object {
    $_ | Set-ADObject -ProtectedFromAccidentalDeletion:$false -PassThru | Remove-ADOrganizationalUnit -Confirm:$false
}

