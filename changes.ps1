# Get the DNS server addresses
$dnsServers = (Get-DnsClientServerAddress).ServerAddresses

# Filter for IPv4 addresses
$ipv4DnsServers = $dnsServers | Where-Object { $_ -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' }
# Output the IPv4 DNS servers
if ($ipv4DnsServers -contains "127.0.0.1") {
    Write-Host "Your DNS server is set to localhost (127.0.0.1)." -ForegroundColor Green
} 
else
{
    Write-Host "You are not using localhost as a DNS Server. `n`nYour DNS servers are:" -ForegroundColor Yellow
    $ipv4DnsServers
}


######################################################################

# Check if DNS is working
$dnsTest = Resolve-DnsName www.google.com -ErrorAction SilentlyContinue

if ($dnsTest) {
    Write-Host "DNS is working correctly." -ForegroundColor Green
} else {
    Write-Host "DNS is not working. Please check your network connection and DNS settings." -ForegroundColor Red
}


########################################################################


$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "The current user has administrative privileges." -ForegroundColor Green
} else {
    Write-Host "The current user does not have administrative privileges. Please run this script with administrative privileges." -ForegroundColor Red
    Exit
}


#####################################################################

    $newHostname = "$($lab.hostname)"
    Rename-Computer -NewName $newHostname -Force -Restart












# Check domain controller services
Get-Service -Name NTDS, Kdc, DnsServer, NetLogon | Select-Object Name, Status

# Check domain controller event logs
Get-EventLog -LogName System, Application, Directory Service -EntryType Error, Warning -Newest 100 | Format-List

# Check domain controller replication
repadmin /replsummary

# Check domain controller DNS
Get-DnsServerDiagnostics

# Check domain controller networking
Get-NetIPConfiguration
Get-NetIPAddress
Get-NetRoute
Get-NetTCPConnection
Get-NetFirewallRule

# Check domain controller Active Directory
dcdiag /v
dcdiag /test:DNS
repadmin /showrepl
nltest /dsgetdc:mydomain.com




diag /v
$dcdiagOutput = dcdiag /v
if ($LASTEXITCODE -ne 0) {
    Write-Warning "DCDiag verbose test failed with exit code $LASTEXITCODE"
}

# Test dcdiag /test:DNS
$dcdiagDNSOutput = dcdiag /test:DNS
if ($LASTEXITCODE -ne 0) {
    Write-Warning "DCDiag DNS test failed with exit code $LASTEXITCODE"
}

# Test repadmin /showrepl
$repadminOutput = repadmin /showrepl
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Repadmin showrepl test failed with exit code $LASTEXITCODE"
}

# Test nltest /dsgetdc:mydomain.com
$nltestOutput = nltest /dsgetdc:mydomain.com
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Nltest dsgetdc test failed with exit code $LASTEXITCODE"
}

# Test critical domain controller services
$services = Get-Service -Name NTDS, Kdc, DnsServer, NetLogon
foreach ($service in $services) {
    if ($service.Status -ne 'Running') {
        Write-Warning "$($service.Name) service is not running"
    }
}