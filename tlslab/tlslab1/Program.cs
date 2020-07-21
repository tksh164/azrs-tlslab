using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace tlslab1
{
    class Program
    {
        private static bool IsSkipCertificateValidation = false;

        static void Main(string[] args)
        {
            if (args.Length < 2 || args.Length == 3)
            {
                Console.WriteLine(@"Usage: tlslab url cert_validation_skip_flag [proxy_address proxy_port]");
                Console.WriteLine();
                Console.WriteLine(@"Example:");
                Console.WriteLine(@"  tlslab1 https://login.windows.net/ false");
                Console.WriteLine(@"  tlslab1 https://login.windows.net/ false 192.0.2.10 3128");
                Console.WriteLine(@"  tlslab1 https://login.windows.net/ true 192.0.2.10 3128");
                return;
            }

            var url = args[0];
            var skipCertificateValidationFlag = bool.Parse(args[1]);
            IsSkipCertificateValidation = skipCertificateValidationFlag;
            string proxyAddress = null;
            int proxyPort = 0;
            if (args.Length >= 4)
            {
                proxyAddress = args[2];
                proxyPort = int.Parse(args[3]);
            }

            Console.WriteLine(@"URL: {0}", url);
            Console.WriteLine(@"Skip Certificate Validation Flag: {0}", IsSkipCertificateValidation);
            Console.WriteLine(@"Proxy Address: {0}", proxyAddress);
            Console.WriteLine(@"Proxy Port: {0}", proxyPort);

            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(CertificateValidationCallback);

            try
            {
                string response;
                using (var client = new WebClient())
                {
                    if (string.IsNullOrEmpty(proxyAddress) && proxyPort != 0)
                    {
                        client.Proxy = new WebProxy(proxyAddress, proxyPort);
                    }

                    using (var stream = client.OpenRead(url))
                    using (var reader = new StreamReader(stream, Encoding.UTF8))
                    {
                        response = reader.ReadToEnd();
                    }
                }

                if (response != null)
                {
                    Console.WriteLine(response);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("Exception:");
                Console.WriteLine(ex.ToString());
            }
        }

        private static bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (IsSkipCertificateValidation)
            {
                Console.WriteLine("Skip certification validation (The validation result is always returned as valid).");
                return true;
            }

            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                Console.WriteLine("Certification validation completed with no error.");
                return true;
            }
            else
            {
                Console.WriteLine("Certification validation completed with error.");
                Console.WriteLine("Errors:");
                Console.WriteLine(sslPolicyErrors.ToString());
                return false;
            }
        }
    }
}
