#requires -Version 4

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string] $VaultCredentialsFilePath,

    [Parameter(Mandatory = $false)]
    [string] $ProxyAddress,

    [Parameter(Mandatory = $false)]
    [int] $ProxyPort
)

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

# Load the ADAL.
$adalDllPath = Join-Path -Path $PSScriptRoot -ChildPath 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
Add-Type -LiteralPath $adalDllPath

# Add the HttpClientFactory class for ADAL.
try
{
Add-Type -TypeDefinition @'
using System.Net.Http;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

public class AdalHttpClientFactory : IHttpClientFactory
{
    private readonly HttpClient httpClient;

    public AdalHttpClientFactory(HttpClientHandler httpClientHandler)
    {
        httpClient = new HttpClient(httpClientHandler);
    }

    public HttpClient GetHttpClient()
    {
        return httpClient;
    }
}
'@ -Language CSharp -ReferencedAssemblies 'System.Net.Http.dll',$adalDllPath -ErrorAction Continue
}
catch
{
    if ($Error[0].FullyQualifiedErrorId -ne 'TYPE_ALREADY_EXISTS,Microsoft.PowerShell.Commands.AddTypeCommand') { throw }    
}

$scriptParams = @{
    VaultCredentialsFilePath = $VaultCredentialsFilePath
    UseProxy                 = $PSBoundParameters.ContainsKey('ProxyAddress') -and $PSBoundParameters.ContainsKey('ProxyPort')
    ProxyAddress             = if ($PSBoundParameters.ContainsKey('ProxyAddress')) { $ProxyAddress } else { $null }
    ProxyPort                = if ($PSBoundParameters.ContainsKey('ProxyPort')) { $ProxyPort } else { $null }
}

# Print the parameters.
Write-Host ('VaultCredentials file: {0}' -f $scriptParams.VaultCredentialsFilePath)
$proxyText = if ($scriptParams.UseProxy) { '{0}:{1}' -f $scriptParams.ProxyAddress, $scriptParams.ProxyPort } else { 'no proxy' }
Write-Host ('Proxy: {0}' -f $proxyText)

# Read the *.VaultCredentials file.
[xml] $vaultCredentialsFileData = Get-Content -LiteralPath $scriptParams.VaultCredentialsFilePath -Encoding utf8
$aadAuthority = $vaultCredentialsFileData.RSBackupVaultAADCreds.AadAuthority
$aadTenantId = $vaultCredentialsFileData.RSBackupVaultAADCreds.AadTenantId
$clientId = $vaultCredentialsFileData.RSBackupVaultAADCreds.ServicePrincipalClientId
$base64EncodedCertBytes = [Convert]::FromBase64String($vaultCredentialsFileData.RSBackupVaultAADCreds.ManagementCert)

# Create an authenticate context.
$httpClientHandler = New-Object -TypeName 'System.Net.Http.HttpClientHandler'
$httpClientHandler.SslProtocols = [System.Security.Authentication.SslProtocols]::Tls12  # Set the TLS version used to communication with Azure AD.
$httpClientHandler.UseProxy = $scriptParams.UseProxy
if ($scriptParams.UseProxy)
{
    # Set the proxy IP address and port for the authenticate communication with Azure AD.
    $httpClientHandler.Proxy = New-Object -TypeName 'System.Net.WebProxy' -ArgumentList ('{0}:{1}' -f $scriptParams.ProxyAddress, $scriptParams.ProxyPort)
}
$httpClientFactory = New-Object -TypeName 'AdalHttpClientFactory' -ArgumentList $httpClientHandler
$authContrxtUrl = $aadAuthority + '/' + $aadTenantId
$authContext = New-Object -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext' -ArgumentList $authContrxtUrl, $false, $null, $httpClientFactory

# Create a credential for acquire token.
$managementCert = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Certificate2'
$managementCert.Import($base64EncodedCertBytes)
$credental = New-Object -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate' -ArgumentList $clientId, $managementCert

try
{
    # Get the access token from Azure AD.
    $resource = 'https://management.azure.com/'
    $result = $authContext.AcquireTokenAsync($resource, $credental)
    $result.Wait()
    Write-Host ''
    Write-Host ('Access token: {0}' -f $result.Result.AccessToken)
}
catch
{
    Write-Error -Message $Error[0].Exception.ToString() -ErrorAction Continue
}
