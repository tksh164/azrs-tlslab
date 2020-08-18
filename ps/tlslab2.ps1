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

# Load ADAL.
$adalDllPath = Join-Path -Path $PSScriptRoot -ChildPath 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
Add-Type -LiteralPath $adalDllPath

# Add HttpClientFactory for ADAL.
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

# Print the parameters.
Write-Host ('VaultCredentials file: {0}' -f $VaultCredentialsFilePath)
$proxyAddressPort = $null
if ($PSBoundParameters.ContainsKey('ProxyAddress') -and $PSBoundParameters.ContainsKey('ProxyPort'))
{
    Write-Host ('Proxy address: {0}' -f $ProxyAddress)
    Write-Host ('Proxy port: {0}' -f $ProxyPort)
    $proxyAddressPort = ('{0}:{1}' -f $ProxyAddress, $ProxyPort)
}

# Read the *.VaultCredentials file.
[xml] $vaultCredentialsFileData = Get-Content -LiteralPath $VaultCredentialsFilePath -Encoding utf8
$aadAuthority = $vaultCredentialsFileData.RSBackupVaultAADCreds.AadAuthority
$aadTenantId = $vaultCredentialsFileData.RSBackupVaultAADCreds.AadTenantId
$clientId = $vaultCredentialsFileData.RSBackupVaultAADCreds.ServicePrincipalClientId
$base64EncodedCertBytes = [Convert]::FromBase64String($vaultCredentialsFileData.RSBackupVaultAADCreds.ManagementCert)

# Create an authenticate context.
$httpClientHandler = New-Object -TypeName 'System.Net.Http.HttpClientHandler'
if ($proxyAddressPort -ne $null)
{
    $httpClientHandler.Proxy = New-Object -TypeName 'System.Net.WebProxy' -ArgumentList $proxyAddressPort
}
$httpClientFactory = New-Object -TypeName 'AdalHttpClientFactory' -ArgumentList $httpClientHandler
$authContrxtUrl = $aadAuthority + '/' + $aadTenantId
$authContext = New-Object -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext' -ArgumentList $authContrxtUrl, $false, $null, $httpClientFactory

# Create a credential.
$managementCert = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Certificate2'
$managementCert.Import($base64EncodedCertBytes)
$credental = New-Object -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate' -ArgumentList $clientId, $managementCert

try
{
    # Retrieve the access token from Azure AD.
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
