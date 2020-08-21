using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace tlslab2
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine(@"Usage: tlslab2 vault_credentials_file_path proxy_address proxy_port");
                Console.WriteLine();
                Console.WriteLine(@"Example:");
                Console.WriteLine(@"  tlslab2 ""C:\work\lab1_Wed Jul 22 2020.VaultCredentials"" 192.0.2.10 3128");
                return;
            }
            var vaultCredentialsFilePath = args[0];
            var proxyAddress = args[1];
            var proxyPort = int.Parse(args[2]);

            Console.WriteLine(@"Vault Credentials File Path: ""{0}""", vaultCredentialsFilePath);
            Console.WriteLine(@"Proxy Address: {0}", proxyAddress);
            Console.WriteLine(@"Proxy Port: {0}", proxyPort);

            // Read the vault credentials data from the *.VaultCredentials file.
            var vaultCredentialsData = new VaultCredentialsData(vaultCredentialsFilePath);

            var authContextUrl = vaultCredentialsData.AadAuthority + "/" + vaultCredentialsData.AadTenantId;
            var httpClientHandler = new HttpClientHandler()
            {
                SslProtocols = SslProtocols.Tls12,  // Set the TLS version used to communication with Azure AD.
                UseProxy = true,
                Proxy = new WebProxy(string.Format("{0}:{1}", proxyAddress, proxyPort)),
                //UseDefaultCredentials = true,
            };
            var authContext = new AuthenticationContext(authContextUrl, false, null, new AdalHttpClientFactory(httpClientHandler));

            var managementCert = new X509Certificate2();
            managementCert.Import(vaultCredentialsData.ManagementCertificateRawData);
            var credential = new ClientAssertionCertificate(vaultCredentialsData.ClientId, managementCert);

            try
            {
                const string resource = "https://management.azure.com/";
                var result = authContext.AcquireTokenAsync(resource, credential);
                result.Wait();
                Console.WriteLine("AccessToken: {0}", result.Result.AccessToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("Exception:");
                Console.WriteLine(ex.ToString());
            }
        }
    }

    internal class VaultCredentialsData
    {
        public string AadAuthority { get; private set; }
        public string AadTenantId { get; private set; }
        public string ClientId { get; private set; }
        public byte[] ManagementCertificateRawData { get; private set; }

        public VaultCredentialsData(string vaultCredentialsFilePath)
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.Load(vaultCredentialsFilePath);
            var nsManager = new XmlNamespaceManager(xmlDoc.NameTable);
            nsManager.AddNamespace("i", "http://www.w3.org/2001/XMLSchema-instance");
            nsManager.AddNamespace("c", "http://schemas.datacontract.org/2004/07/Microsoft.Azure.Portal.RecoveryServices.Models.Common");

            AadAuthority = xmlDoc.SelectSingleNode("/c:RSBackupVaultAADCreds/c:AadAuthority", nsManager).InnerText;
            AadTenantId = xmlDoc.SelectSingleNode("/c:RSBackupVaultAADCreds/c:AadTenantId", nsManager).InnerText;
            ClientId = xmlDoc.SelectSingleNode("/c:RSBackupVaultAADCreds/c:ServicePrincipalClientId", nsManager).InnerText;
            var base64EncodedCertData = xmlDoc.SelectSingleNode("/c:RSBackupVaultAADCreds/c:ManagementCert", nsManager).InnerText;
            ManagementCertificateRawData = GetCertificateRawData(base64EncodedCertData);
        }

        private static byte[] GetCertificateRawData(string base64EncodedCertificate)
        {
            return Convert.FromBase64String(base64EncodedCertificate);
        }
    }

    internal class AdalHttpClientFactory : IHttpClientFactory
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
}
