using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class SecondClient
{
    public static void Main()
    {
        try
        {
            IPAddress ipAddress = IPAddress.Loopback;
            int port = 7180;
            IPEndPoint ipEndPoint = new IPEndPoint(ipAddress, port);

            using (Socket client = new Socket(ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
            {
                client.Connect(ipEndPoint);

                var buffer = new byte[4096];
                int bytesReceived = client.Receive(buffer);
                var receivedData = Encoding.UTF8.GetString(buffer, 0, bytesReceived);
                var parts = receivedData.Split(':');
                var message = parts[0];
                var signature = Convert.FromBase64String(parts[1]);
                var publicKeyXml = parts[2];

                bool isSignatureValid = VerifySignature(message, signature, publicKeyXml);
                if (isSignatureValid)
                {
                    Console.WriteLine($"Received message: \"{message}\"");
                    Console.WriteLine("The signature is valid.");
                }
                else
                {
                    Console.WriteLine("Invalid signature.");
                }

                client.Shutdown(SocketShutdown.Both);
                client.Close();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
    }

    private static bool VerifySignature(string data, byte[] signature, string publicKeyXml)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.FromXmlString(publicKeyXml);
            var dataBytes = Encoding.UTF8.GetBytes(data);
            return rsa.VerifyData(dataBytes, new SHA256CryptoServiceProvider(), signature);
        }
    }
}
