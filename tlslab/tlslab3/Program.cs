using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace tlslab3
{
    class Program
    {
        private static bool IsSkipCertificateValidation = false;

        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine(@"Usage: tlslab3 remote_host proxy_address proxy_port [skip_cert_validation]");
                Console.WriteLine();
                Console.WriteLine(@"Example:");
                Console.WriteLine(@"  tlslab3 login.windows.net 192.0.2.10 3128");
                Console.WriteLine(@"  tlslab3 login.windows.net 192.0.2.10 3128 false");
                Console.WriteLine(@"  tlslab3 login.windows.net 192.0.2.10 3128 true");
                return;
            }

            var remoteHost = args[0];
            var proxyAddress = args[1];
            var proxyPort = int.Parse(args[2]);
            var skipCertificateValidationFlag = args.Length >= 4 ? bool.Parse(args[3]) : false;
            IsSkipCertificateValidation = skipCertificateValidationFlag;

            Console.WriteLine(@"Remote Host: {0}", remoteHost);
            Console.WriteLine(@"Proxy Address: {0}", proxyAddress);
            Console.WriteLine(@"Proxy Port: {0}", proxyPort);
            Console.WriteLine(@"Skip Certificate Validation Flag: {0}", IsSkipCertificateValidation);

            using (var tcpClient = new TcpClient())
            {
                var ipAddresses = Dns.GetHostAddresses(proxyAddress);
                tcpClient.Connect(new IPEndPoint(ipAddresses[0], proxyPort));

                // Connect to the proxy using the CONNECT method.
                SendReceiveHttpConnectMethod(tcpClient.GetStream(), remoteHost);

                using (var sslStream = new SslStream(tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(CertificateValidationCallback)))
                {
                    try
                    {
                        // Validate the certificate.
                        sslStream.AuthenticateAsClient(remoteHost);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine();
                        Console.WriteLine("Exception:");
                        Console.WriteLine(ex.ToString());
                    }
                }
            }
        }

        private static void SendReceiveHttpConnectMethod(Stream tcpStream, string host)
        {
            var request = string.Format("CONNECT {0}:{1} HTTP/1.1\r\nHost:{0}\r\n\r\n", host, 443);
            Console.WriteLine(request);

            var httpRequest = Encoding.UTF8.GetBytes(request);
            tcpStream.Write(httpRequest, 0, httpRequest.Length);
            tcpStream.Flush();

            var receiveBuffer = new byte[4096];
            var receivedBytes = tcpStream.Read(receiveBuffer, 0, receiveBuffer.Length);
            Console.WriteLine(Encoding.UTF8.GetString(receiveBuffer, 0, receivedBytes));
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
