Set-Location $PSScriptRoot

#Checks if user is running the script with admin privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "You are running with administrative privileges. Proceeding with Domain Controller Setup..." -ForegroundColor Green
} else {
    Write-Host "The current user does not have administrative privileges. Please run this script with administrative privileges." -ForegroundColor Red
    Exit
}

# RUNONCE HKLM ################################################################

$labFilePath = "lab.json"

if (Test-Path $labFilePath) {
    $lab = Get-Content $labFilePath | ConvertFrom-Json
    Write-Host ("Successfully retrieved configuration settings from lab.json...") -ForegroundColor Green
} else {
    Write-Error "File not found: $labFilePath. Exiting program..." -ForegroundColor Red
    exit
}

Write-Host "Domain Configuration:"
Write-Host "DomainName: $($lab.DomainName)"
Write-Host "NetBIOSName: $($lab.NetBIOSName)"

Write-Host "`nServer Configuration:"  
Write-Host "Hostname: $($lab.Hostname)"
Write-Host "IPAddress: $($lab.IPAddress)"
Write-Host "SubnetMask: $($lab.SubnetMask)"
Write-Host "DefaultGateway: $($lab.DefaultGateway)"
Write-Host "DNSServers: $($lab.DNSServers -join ', ')"
Write-Host "DNSForwarders: $($lab.DNSForwarders -join ', ')"

Write-Host "`nDirectory Services Configuration:"
Write-Host "DatabasePath: $($lab.DatabasePath)"
Write-Host "LogPath: $($lab.LogPath)"
Write-Host "SysvolPath: $($lab.SysvolPath)"
Write-Host "ForestMode: $($lab.ForestMode)"

Write-Host "`nSecurity Configuration:"
Write-Host "SafeModeAdministratorPassword: $($lab.SafeModeAdministratorPassword)"
Write-Host "UserPassword: $($lab.UserPassword)"
Write-Host "AdminPassword: $($lab.AdminPassword)"

Write-Host "`nOther Configuration:"
Write-Host "UsersFilePath: $($lab.UsersFilePath)"
Write-Host "WindowsFeatures: $($lab.WindowsFeatures -join ', ')"
Write-Host "InstallDNS: $($lab.InstallDNS)"
Write-Host "TimeZone: $($lab.TimeZone)"
Write-Host "RebootOnCompletion: $($lab.RebootOnCompletion)"
Write-Host "Logging: $($lab.Logging)"
Write-Host "NetworkAdapter: $($lab.NetworkAdapter)"
Write-Host "TranscriptLogPath: $($lab.TranscriptLogPath)"

Write-Host ("`n`nPlease look over these configuration settings. Waiting 20 seconds...")
Start-Sleep -Seconds 20

Set-TimeZone -Id $lab.TimeZone

# DYNAMIC TRANSCRIPT NAME ######################################################
if ($lab.logging)
{
    Start-Transcript -Path $lab.TranscriptLogPath
    Write-Host("Logging enabled to  $($lab.TranscriptLogPath)")
}
else {
    Write-Warning "Logging is disabled!"
}

function Set-StaticIP {
    param (
        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$DefaultGateway,
        [string[]]$DNSServers
    )
    if (-not (Test-NetConnection -ComputerName "8.8.8.8" -InformationLevel Quiet)) {
    Write-Host "Prior Network Configuration Failed. `n`n Statically Configuring Address with the Given Config...`n"
    }
    else
    {
        #Check if static address
        #Ask about network configuration
        Write-Host "Prior Network Configuration Succeeded"
    }
    $networkAdapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1

    if ($null -eq $networkAdapter) {
        Write-Error "No active network adapter found. Exiting program now..."-ForegroundColor Red
        exit
    }
 
    try {
        $binarySubnetMask = ([System.Net.IPAddress]::Parse($SubnetMask).GetAddressBytes() | ForEach-Object { [System.Convert]::ToString($_, 2) }) -join ''
        $prefixLength = $binarySubnetMask -replace '0+$'
        $prefixLength = $prefixLength.Length

         New-NetIPAddress `
        -InterfaceAlias $networkAdapter.Name `
        -IPAddress $IPAddress `
        -PrefixLength $prefixLength `
        -DefaultGateway $DefaultGateway -ErrorAction Stop

        Set-DnsClientServerAddress `
            -InterfaceAlias $networkAdapter.Name `
            -ServerAddresses $DNSServers -ErrorAction Stop

        Write-Output "Static IP configuration set successfully. `nTesting network connection..." -ForegroundColor Green

        # Test basic network connectivity
        try {
            $ping = Test-Connection -ComputerName "$DefaultGateway" -Count 1 -ErrorAction Stop
            if ($ping.StatusCode -eq 0) {
                Write-Host "Network connectivity succeeded!" -ForegroundColor Green
            } else {
                Write-Error "No network connectivity."  -ForegroundColor Red
            }
            $ping = Test-Connection -ComputerName "8.8.8.8" -Count 1 -ErrorAction Stop
            if ($ping.StatusCode -eq 0) {
                Write-Host "Internet connectivity succeeded!" -ForegroundColor Green
            } else {
                Write-Error "No internet connectivity."  -ForegroundColor Red
            }
} catch {
    Write-Error "No network connectivity. Exiting program now..." -ForegroundColor Red
    exit
}
    } catch {
        Write-Error "Failed to set static IP configuration. Error: $_" -ForegroundColor Red
        exit
    }
}

# Convert the password to a secure string
$SecureSafeModePassword = ConvertTo-SecureString $lab.SafeModeAdministratorPassword -AsPlainText -Force

# Set static IP address
Set-StaticIP -IPAddress $lab.IPAddress -SubnetMask $lab.SubnetMask -DefaultGateway $lab.DefaultGateway -DNSServers $lab.DNSServers

# Install the AD DS role and DNS role if not already installed
$features = $log.WindowsFeatures
foreach ($feature in $features) {
    try {
        if (-not (Get-WindowsFeature -Name $feature).Installed) {
            Install-WindowsFeature -Name $feature -IncludeManagementTools -Confirm:$false -ErrorAction Stop
            Write-Host "$feature installed successfully." -ForegroundColor Green
        }
        else
        {
            Write-Host "$feature already installed. Moving on..."-ForegroundColor Yellow
        }
    } catch {
        Write-Error "Failed to install $feature. Error: $_" -ForegroundColor Red
        exit
    }
}

# Import the AD DS Deployment module
Import-Module ADDSDeployment

# Install a new forest
try {
    Install-ADDSForest `
        -DomainName $lab.DomainName `
        -DomainNetbiosName $lab.NetBIOSName `
        -SafeModeAdministratorPassword $SecureSafeModePassword `
        -InstallDNS:$lab.InstallDNS `
        -DatabasePath $lab.DatabasePath `
        -LogPath $lab.LogPath `
        -SysvolPath $lab.SysvolPath `
        -ForestMode $lab.ForestMode `
        -Force:$true `
        -NoRebootOnCompletion:$false -ErrorAction Stop
    Write-Host "Forest installation completed successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to install AD DS Forest. Error: $_" -ForegroundColor Red
    exit
}

# Change the hostname of the domain controller
try {
    Rename-Computer -NewName $lab.Hostname -Force -Restart
    Write-Host "Domain controller hostname changed to $($lab.Hostname). The system will now restart." -ForegroundColor Green
} catch {
    Write-Error "Failed to change the hostname. Error: $_" -ForegroundColor Red
}

try {
    Set-DnsServerForwarder -IPAddress $lab.DNSForwarders -UseReversibleEncryption
    Write-Host "DNS forwarders configured successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to configure DNS forwarders. Error: $_" -ForegroundColor Red
}

# Reboot the server if required
if ($lab.RebootOnCompletion) {
    Restart-Computer
    Start-Sleep -Seconds 60  # Wait for the system to reboot and services to start
}

# Wait for Active Directory services to start
Start-Sleep -Seconds 120

# Post-installation verification
try {
    $dcdiagOutput = dcdiag
    if ($dcdiagOutput -notmatch "passed") {
        Write-Error "DC promotion encountered issues. Please review the dcdiag output." -ForegroundColor Red
        Write-Output $dcdiagOutput
        exit
    }
    Write-Output "Domain Controller promotion completed successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to run dcdiag. Error: $_" -ForegroundColor Red
    exit
}

# Import the Active Directory module
Import-Module ActiveDirectory

# Create users from the text file
if (Test-Path $lab.UsersFilePath) {
    $users = Get-Content $lab.UsersFilePath
    Write-Host "Adding Active Directory users to the domain... `nAdmins are denoted with a `* before username (no spaces)."
    foreach ($user in $users) {
        $isAdmin = $false
        if ($user.StartsWith("*")) {
            $isAdmin = $true
            $user = $user.Substring(1).Trim()  # Remove the leading star and trim
        }

        $userDetails = $user -split ',' # Change the delimiter here
        if ($userDetails.Length -ge 3) {
            $username = $userDetails[0]
            $firstName = $userDetails[1]
            $lastName = $userDetails[2]
            $password = if ($isAdmin) { ConvertTo-SecureString $lab.AdminPassword -AsPlainText -Force } elseif ($userDetails.Length -ge 4) { ConvertTo-SecureString $userDetails[3] -AsPlainText -Force } else { ConvertTo-SecureString $lab.UserPassword -AsPlainText -Force }

            try {
                New-ADUser `
                    -Name "$firstName $lastName" `
                    -GivenName $firstName `
                    -Surname $lastName `
                    -SamAccountName $username `
                    -UserPrincipalName "$username@$($lab.DomainName)" `
                    -AccountPassword $password `
                    -Enabled $true `
                    -PasswordNeverExpires $true `
                    -Path "CN=Users,DC=$($lab.DomainName -split '\.')[0],DC=$($lab.DomainName -split '\.')[1]" `
                    -ChangePasswordAtLogon ($isAdmin -eq $false) `
                    -ErrorAction Stop
                
                Write-Output "User $username created successfully." -ForegroundColor Green
            } catch {
                Write-Error "Failed to create user $username. Error: $_" -ForegroundColor Red
            }
        } else {
            Write-Error "Invalid format in users file for line: $user" -ForegroundColor Red
        }
    }
} else {
    Write-Error "Users file not found: $($lab.UsersFilePath)" -ForegroundColor Red
    #How to proceed from here
}

# Stop transcript logging
try {
    Stop-Transcript
} catch {
    Write-Warning "Logging was disabled in configuration" -ForegroundColor Yellow
}

Write-Host "Script has completed! The transcript is available at $($lab.TranscriptLogPath)" -ForegroundColor Green