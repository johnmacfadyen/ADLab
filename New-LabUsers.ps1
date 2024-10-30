# Function to get random user data from the API

$baseOU = "OU=Departments,OU=Employees,OU=Users,OU=GoBrr Health,DC=lab,DC=gobrr,DC=dev"
$groupOU = "OU=Departments,OU=Roles,OU=Groups,OU=GoBrr Health,DC=lab,DC=gobrr,DC=dev"


function Get-RandomUser {
    param (
    [int]$count = 1,
    [string]$nationality = "au",
    [string]$passFormat = "special,upper,lower,number,24-32"
    )
    $url = "https://randomuser.me/api/?results=$count&nat=$nationality&password=$passFormat"
    $response = Invoke-RestMethod -Uri $url -Method Get
    return $response.results
}

$departments = (Get-Content .\depts.json | ConvertFrom-Json -depth 4).departments

$employeeID = 1000

# Iterate through each department and job role
foreach ($department in $departments) {
    $departmentName = $department.name
    $departmentShortName = $department.short_name
    $jobRoles = $department.roles_count
    
    foreach ($role in $jobRoles.PSObject.Properties) {
        $roleName = $role.Name
        $roleCount = $role.Value
        
        if ($roleCount) {
            $randomUsers = Get-RandomUser -count $roleCount
            
            foreach ($user in $randomUsers) {
                # Increment EmployeeID for each new user
                $employeeID++
                
                $firstName = $user.name.first
                $lastName = $user.name.last
                $email = $user.name.first.ToLower() + "." + $user.name.last.ToLower() + "@lab.gobrr.dev"
                $phone = $user.phone -replace "-", " "
                $password = $user.login.password | ConvertTo-SecureString -AsPlainText -Force
                $passwordPlain = $user.login.password # Use the password as the employee number because this is a lab and I want to be able to get the password easily
                $title = $roleName
                $company = "GoBrr Health"
                $description = $roleName
                $SamAccountName = "$($firstName.ToLower()).$($lastName.ToLower())"
                $country = $user.nat
                
                
                # Try to create the new AD user
                try {
                    $newUser = New-ADUser -Name "$firstName $lastName" -DisplayName "$firstName $lastName"  `
                     -GivenName $firstName -Surname $lastName -Company $company -Description $description   `
                     -EmployeeID $employeeID -EmailAddress $email -OfficePhone $phone -Title $title         `
                     -Department $departmentName -Path "OU=$departmentName,$baseOU" -country $country       `
                     -UserPrincipalName $email -SamAccountName $SamAccountName -AccountPassword $password   `
                     -Office $passwordPlain `
                     -Enabled $true -PassThru
                    if ($newUser) {
                        Write-Output "Successfully created user: $firstName $lastName with EmployeeID: $employeeID"
                        
                        
                        # Set the user's profile picture
                        try {
                            $photoUrl = $user.picture.large
                            $photoPath = "C:\pictures\$($lastName.ToLower())\$($firstName.ToLower())_$($lastName.ToLower()).jpg"
                            
                            if (-not (Test-Path (Split-Path $photoPath))) {
                                New-Item -ItemType Directory -Path (Split-Path $photoPath) -Force
                            } 
                            
                            Invoke-WebRequest -Uri $photoUrl -OutFile $photoPath
                            Set-ADUser -Identity $newUser -Replace @{thumbnailPhoto = ([byte[]](Get-Content $photoPath -AsByteStream))}
                        } catch {
                            Write-Error "Error setting profile picture for user $firstName $($lastName): $_"
                        }
                        
                    } else {
                        Write-Output "Failed to create user: $firstName $lastName"
                    }
                } catch {
                    Write-Error "Error creating user $firstName $($lastName): $_"
                }
                
                # Add user to role group if user creation was successful
                if ($newUser) {
                    $roleNameFormatted = "Role.$($departmentShortName).$($roleName)" -replace " ", "_"
                    $roleGroup = Get-ADGroup -Filter { Name -eq $roleNameFormatted } -SearchBase "OU=$departmentName,$groupOU"
                    if ($roleGroup) {
                        try {
                            Add-ADGroupMember -Identity $roleGroup -Members $newUser
                            Write-Output "Added user $firstName $lastName to group $roleNameFormatted"
                        } catch {
                            Write-Error "Error adding user $firstName $lastName to group $($roleNameFormatted): $_"
                        }
                    } else {
                        Write-Error "Role group $roleNameFormatted not found for user $firstName $lastName"
                    }
                }
            }
        }
    }
}

$EmployeeOUs = Get-ADOrganizationalUnit -SearchBase $baseOu -Filter * -SearchScope OneLevel


# Set all users to report to the user with the title "Head of Department"
foreach ($ou in $EmployeeOUs) {
    
    if ($ou.Name -like "*Executive*") {
        $ceo = Get-ADUser -Filter { Title -like "*CEO*" } -SearchBase $baseOU
        $users = Get-ADUser -SearchBase $ou.DistinguishedName -Filter * -Properties Title
        
        $users | ForEach-Object {
            # Skip setting the CEO to report to themselves
            if ($_.DistinguishedName -ne $ceo.DistinguishedName) {
                Set-ADUser -Identity $_ -Manager $ceo.DistinguishedName
            }
        }
    } else {
        $users = Get-ADUser -SearchBase $ou.DistinguishedName -Filter * -Properties Title
        
        $headOf = $users | Where-Object { $_.Title -like "*Head of*" -or $_.Title -like "*Chief*" -or $_.Title -like "Hospital Administrator" -or $_.Title -like "*CEO*"}
        
        if ($headOf) {
            $headOfDn = $headOf.DistinguishedName
            $users | ForEach-Object {
                if ($_.DistinguishedName -ne $headOfDn) {
                    try {
                        Set-ADUser -Identity $_ -Manager $headOfDn
                    } catch {
                        Write-Error "Error setting manager for user $($_.Name): $_"
                    }
                }
            }
        }
        
        # Set the head of department to report to the CEO
        $ceo = Get-ADUser -Filter { Title -like "*CEO*" } -SearchBase $baseOU
        if ($ceo) {
            $headOf | ForEach-Object {
                Set-ADUser -Identity $_ -Manager $ceo.DistinguishedName
            }
        }
    }
}

# Find users without a manager
# Wait 30 seconds for replication to occur
Start-Sleep -Seconds 30
$usersWithoutManager = Get-ADUser -LDAPFilter "(!manager=*)" -Properties * -SearchBase $baseOU

$usersWithoutManager | ForEach-Object {
    if ($_.Title -like "*CEO*") {
        Write-Output "User $($_.Name) is the CEO and does not have a manager"
        return
    } else {
        Write-Output "User $($_.Name) does not have a manager"
    }
}