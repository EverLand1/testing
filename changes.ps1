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