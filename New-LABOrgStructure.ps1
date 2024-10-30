# Build Base OU Structure
$baseDN = "DC=lab,DC=gobrr,DC=dev"
$orgName = "GoBrr Health"

try {
    New-ADOrganizationalUnit -Name "GoBrr Health" -Path $baseDN -Description "The main organizational unit for GoBrr Health" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: $orgName already exists"
    } else {
        Write-Host "Error creating OU: $orgName - $($error[0].Exception.Message)"
    }
}

$orgOU = "OU=$orgName,$baseDN"

# Create the Computers OU
try {
    New-ADOrganizationalUnit -Name "Computers" -Path $orgOU -Description "The organizational unit for all computer objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Computers already exists"
    } else {
        Write-Host "Error creating OU: Computers - $($error[0].Exception.Message)"
    }
}

# Create the Servers OU
try {
    New-ADOrganizationalUnit -Name "Servers" -Path "OU=Computers,$orgOU" -Description "The organizational unit for all server objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Servers already exists"
    } else {
        Write-Host "Error creating OU: Servers - $($error[0].Exception.Message)"
    }
}

# Create Application Servers OU under Servers
try {
    New-ADOrganizationalUnit -Name "Application Servers" -Path "OU=Servers,OU=Computers,$orgOU" -Description "The organizational unit for all application server objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Application Servers already exists"
    } else {
        Write-Host "Error creating OU: Application Servers - $($error[0].Exception.Message)"
    }
}

# Create Database Servers OU under Servers
try {
    New-ADOrganizationalUnit -Name "Database Servers" -Path "OU=Servers,OU=Computers,$orgOU" -Description "The organizational unit for all database server objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Database Servers already exists"
    } else {
        Write-Host "Error creating OU: Database Servers - $($error[0].Exception.Message)"
    }
}

# Create Web Servers OU under Servers
try {
    New-ADOrganizationalUnit -Name "Web Servers" -Path "OU=Servers,OU=Computers,$orgOU" -Description "The organizational unit for all web server objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Web Servers already exists"
    } else {
        Write-Host "Error creating OU: Web Servers - $($error[0].Exception.Message)"
    }
}

# Create the Workstations OU
try {
    New-ADOrganizationalUnit -Name "Workstations" -Path "OU=Computers,$orgOU" -Description "The organizational unit for all workstation objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Workstations already exists"
    } else {
        Write-Host "Error creating OU: Workstations - $($error[0].Exception.Message)"
    }
}

# Create the Desktops and Laptops OU under Workstations
try {
    New-ADOrganizationalUnit -Name "Desktops" -Path "OU=Workstations,OU=Computers,$orgOU" -Description "The organizational unit for all desktop computer objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Desktops already exists"
    } else {
        Write-Host "Error creating OU: Desktops - $($error[0].Exception.Message)"
    }
}

try {
    New-ADOrganizationalUnit -Name "Laptops" -Path "OU=Workstations,OU=Computers,$orgOU" -Description "The organizational unit for all laptop computer objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Laptops already exists"
    } else {
        Write-Host "Error creating OU: Laptops - $($error[0].Exception.Message)"
    }
}

# Create the Groups OU
try {
    New-ADOrganizationalUnit -Name "Groups" -Path $orgOU -Description "The organizational unit for all group objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Groups already exists"
    } else {
        Write-Host "Error creating OU: Groups - $($error[0].Exception.Message)"
    }
}

# Create the Roles OU under Groups
try {
    New-ADOrganizationalUnit -Name "Roles" -Path "OU=Groups,$orgOU" -Description "The organizational unit for all role objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Roles already exists"
    } else {
        Write-Host "Error creating OU: Roles - $($error[0].Exception.Message)"
    }
}

# Create the Admins OU under Roles
try {
    New-ADOrganizationalUnit -Name "Admins" -Path "OU=Roles,OU=Groups,$orgOU" -Description "The organizational unit for all admin role objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Admins already exists"
    } else {
        Write-Host "Error creating OU: Admins - $($error[0].Exception.Message)"
    }
}

# Create the Departments OU under Roles
try {
    New-ADOrganizationalUnit -Name "Departments" -Path "OU=Roles,OU=Groups,$orgOU" -Description "The organizational unit for all department role objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Departments already exists"
    } else {
        Write-Host "Error creating OU: Departments - $($error[0].Exception.Message)"
    }
}

# Create the Projects OU under Roles
try {
    New-ADOrganizationalUnit -Name "Projects" -Path "OU=Roles,OU=Groups,$orgOU" -Description "The organizational unit for all project role objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Projects already exists"
    } else {
        Write-Host "Error creating OU: Projects - $($error[0].Exception.Message)"
    }
}

# Create the Users OU
try {
    New-ADOrganizationalUnit -Name "Users" -Path $orgOU -Description "The organizational unit for all user objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Users already exists"
    } else {
        Write-Host "Error creating OU: Users - $($error[0].Exception.Message)"
    }
}

# Create the Employees OU under Users
try {
    New-ADOrganizationalUnit -Name "Employees" -Path "OU=Users,$orgOU" -Description "The organizational unit for all employee user objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Employees already exists"
    } else {
        Write-Host "Error creating OU: Employees - $($error[0].Exception.Message)"
    }
}

# Create the Departments OU under Employees
try {
    New-ADOrganizationalUnit -Name "Departments" -Path "OU=Employees,OU=Users,$orgOU" -Description "The organizational unit for all department employee objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Departments already exists"
    } else {
        Write-Host "Error creating OU: Departments - $($error[0].Exception.Message)"
    }
}

# Create the Contractors OU under Users
try {
    New-ADOrganizationalUnit -Name "Contractors" -Path "OU=Users,$orgOU" -Description "The organizational unit for all contractor user objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Contractors already exists"
    } else {
        Write-Host "Error creating OU: Contractors - $($error[0].Exception.Message)"
    }
}

# Create the Service Accounts OU under Users
try {
    New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=Users,$orgOU" -Description "The organizational unit for all service account user objects" -Country "AU" -State "VIC" -City "Melbourne"
} catch {
    if ($error[0] -like "*directory with a name that is already in use*") {
        Write-Host "OU: Service Accounts already exists"
    } else {
        Write-Host "Error creating OU: Service Accounts - $($error[0].Exception.Message)"
    }
}


# Define the base OU
$baseOU = "OU=Departments,OU=Employees,OU=Users,$orgOU"
$groupOu = "OU=Departments,OU=Roles,OU=Groups,$orgOU"

# Load the departments from the JSON file
$departments = (Get-Content .\depts.json | ConvertFrom-Json -Depth 4).departments


# Create OUs and groups
foreach ($department in $departments) {

    $departmentName = $department.name
    $departmentDescription = $department.description
    $departmentShortName = $department.short_name

    try {
        New-ADOrganizationalUnit -Name $departmentName -Path $baseOU -Description $departmentDescription -Country "AU" -State "VIC" -City "Melbourne"
    } catch {
        if ($error[0] -like "*directory with a name that is already in use*") {
            #Write-Host "OU: $department already exists"
        } else {
            Write-Host "Error creating OU: $department - $($error[0].Exception.Message)"
        }
    }
    
    $groupPath = "OU=$departmentName,$groupOu"

    try {
        New-ADOrganizationalUnit -Name $departmentName -Path $groupOu
    } catch {
        if ($error[0] -like "*directory with a name that is already in use*") {
            #Write-Host "OU: $department already exists"
        } else {
            Write-Host "Error creating OU: $departmentName - $($error[0].Exception.Message)"
        }
    }
    
    foreach ($role in $department.job_roles) {

        $roleName = "Role.$($departmentShortName).$($role)" -replace " ", "_" 

        Try {
            New-ADGroup -Name $roleName -Path $groupPath -GroupScope Global -GroupCategory Security
        } Catch {
            if ($error[0] -like "*already exists*") {
                #Write-Host "Group: $role already exists in OU: $department"
            } else {
                Write-Host "Error creating group: $roleName - $($error[0].Exception.Message)"
            }
        }
    }
}

# Create Service Account to join computers to the domain
$serviceAccountName = "svc-pcjoiner"
$serviceAccountDescription = "Service account to join computers to the domain"

$serviceAccount = New-ADUser -Name $serviceAccountName -Path "OU=Service Accounts,OU=Users,$orgOU" -Description $serviceAccountDescription `
    -Country "AU" -State "VIC" -City "Melbourne" -AccountPassword (ConvertTo-SecureString "SomePassword" -AsPlainText -Force) `
    -Enabled $true -PassThru -CannotChangePassword $true -PasswordNeverExpires $true -SamAccountName $serviceAccountName -UserPrincipalName "$($serviceAccountName)@lab.gobrr.dev"

# Set the service account to have the "Join a computer to the domain" permission in the domain
$serviceAccountSID = (Get-ADUser $serviceAccountName).SID
$serviceAccountACE = [System.Security.Principal.SecurityIdentifier]::new($serviceAccountSID)
$serviceAccountACE = $serviceAccountACE.Translate([System.Security.Principal.NTAccount])

$domain = Get-ADDomain
$domainSID = $domain.DomainSID
$domainACE = [System.Security.Principal.SecurityIdentifier]::new($domainSID)
$domainACE = $domainACE.Translate([System.Security.Principal.NTAccount])

$domainACL = Get-ACL "AD:\$($domainACE.Value)"
$domainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $serviceAccountACE, "ExtendedRight", "DS-Replication-Get-Changes", "Allow"))