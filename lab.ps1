Set-Location $PSScriptRoot

$lab = Get-Content "lab.json" | ConvertFrom-JSON
<#$lab = Get-Content ".\lab.conf" | ConvertFrom-StringData

$lab = @{}
$lines = Get-Content "lab.conf"
foreach ($line in $lines) {
    $parts = $line.Split('= ', 2)
    if ($parts.Length -eq 2) {
        $lab[$parts[0].Trim()] = $parts[1].Trim()
    }
}
#>
# Start transcript logging
Start-Transcript -Path $lab.TranscriptLogPath

function Set-StaticIP {
    param (
        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$DefaultGateway,
        [string[]]$DNSServers
    )

    $networkAdapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1

    if ($null -eq $networkAdapter) {
        Write-Error "No active network adapter found."
        exit
    }
 
    try {
        New-NetIPAddress `
            -InterfaceAlias $networkAdapter.Name `
            -IPAddress $IPAddress `
            -PrefixLength (32 - [math]::Log([math]::Pow([int][convert]::ToUInt32([convert]::ToUInt32("1".PadLeft($SubnetMask.Split(".").Count() * 8, "1"), 2) -bxor -1), 10)) / [math]::Log(2)) `
            -DefaultGateway $DefaultGateway -ErrorAction Stop

        Set-DnsClientServerAddress `
            -InterfaceAlias $networkAdapter.Name `
            -ServerAddresses $DNSServers -ErrorAction Stop

        Write-Output "Static IP configuration set successfully."

        # Test basic network connectivity
        if (-not (Test-NetConnection -ComputerName "8.8.8.8" -Ping -WarningAction SilentlyContinue)) {
            Write-Error "No network connectivity."
        }

    } catch {
        Write-Error "Failed to set static IP configuration. Error: $_"
        exit
    }
}

# Convert the password to a secure string
$SecureSafeModePassword = ConvertTo-SecureString $lab.SafeModeAdministratorPassword -AsPlainText -Force

# Set static IP address
Set-StaticIP -IPAddress $lab.IPAddress -SubnetMask $lab.SubnetMask -DefaultGateway $lab.DefaultGateway -DNSServers $lab.DNSServers

# Install the AD DS role and DNS role if not already installed
$features = @("AD-Domain-Services", "DNS")
foreach ($feature in $features) {
    try {
        if (-not (Get-WindowsFeature -Name $feature).Installed) {
            Install-WindowsFeature -Name $feature -IncludeManagementTools -Confirm:$false -ErrorAction Stop
            Write-Output "$feature installed successfully."
        }
    } catch {
        Write-Error "Failed to install $feature. Error: $_"
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
    Write-Output "Forest installation completed successfully."
} catch {
    Write-Error "Failed to install AD DS Forest. Error: $_"
    exit
}

try {
    Set-DnsServerForwarder -IPAddress $lab.DNSForwarders -UseReversibleEncryption
    Write-Output "DNS forwarders configured successfully."
} catch {
    Write-Error "Failed to configure DNS forwarders. Error: $_"
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
        Write-Error "DC promotion encountered issues. Please review the dcdiag output."
        Write-Output $dcdiagOutput
        exit
    }
    Write-Output "Domain Controller promotion completed successfully."
} catch {
    Write-Error "Failed to run dcdiag. Error: $_"
    exit
}

# Import the Active Directory module
Import-Module ActiveDirectory

# Create users from the text file
if (Test-Path $lab.UsersFilePath) {
    $users = Get-Content $lab.UsersFilePath
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
                
                Write-Output "User $username created successfully."
            } catch {
                Write-Error "Failed to create user $username. Error: $_"
            }
        } else {
            Write-Error "Invalid format in users file for line: $user"
        }
    }
} else {
    Write-Error "Users file not found: $($lab.UsersFilePath)"
}


# Stop transcript logging
Stop-Transcript

Write-Host "Script has completed! The transcript is available at $($lab.TranscriptLogPath)"