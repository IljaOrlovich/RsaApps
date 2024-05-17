using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class Server
{
    private static RSAParameters _privateKey;
    private static RSAParameters _publicKey;

    static void Main()
    {
        try
        {
            AssignNewKey();

            IPAddress ipAddress = IPAddress.Loopback;
            int port = 7180;
            IPEndPoint ipEndPoint = new IPEndPoint(ipAddress, port);

            using (Socket listener = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
            {
                listener.Bind(ipEndPoint);
                listener.Listen(10);

                Console.WriteLine("Waiting for the first client to connect...");
                using (Socket handlerFirst = listener.Accept())
                {
                    Console.WriteLine("First client connected.");
                    var buffer = new byte[4096];
                    int bytesReceived = handlerFirst.Receive(buffer);
                    var receivedData = Encoding.UTF8.GetString(buffer, 0, bytesReceived);
                    Console.WriteLine($"Received from first client: {receivedData}");

                    var parts = receivedData.Split(':');
                    var message = parts[0];
                    var signature = parts[1];
                    var publicKeyXml = parts[2];

                    Console.WriteLine("Do you want to modify the signature? (yes/no)");
                    var response = Console.ReadLine().ToLower();
                    if (response == "yes")
                    {
                        Console.WriteLine("Enter new text to create fake signature:");
                        var fakeText = Console.ReadLine();
                        var newSignature = Convert.ToBase64String(SignData(fakeText));
                        receivedData = $"{message}:{newSignature}:{publicKeyXml}";
                        buffer = Encoding.UTF8.GetBytes(receivedData);
                        bytesReceived = buffer.Length;
                    }

                    handlerFirst.Shutdown(SocketShutdown.Both);
                    handlerFirst.Close();

                    Console.WriteLine("Waiting for the second client to connect...");
                    using (Socket handlerSecond = listener.Accept())
                    {
                        Console.WriteLine("Second client connected. Sending data...");

                        var updatedPublicKeyXml = ExportPublicKey();
                        var privateKeyXml = ExportPrivateKey();
                        var updatedData = $"{receivedData}:{updatedPublicKeyXml}:{privateKeyXml}";
                        var updatedBuffer = Encoding.UTF8.GetBytes(updatedData);
                        handlerSecond.Send(updatedBuffer, updatedBuffer.Length, SocketFlags.None);

                        handlerSecond.Shutdown(SocketShutdown.Both);
                        handlerSecond.Close();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
    }

    private static void AssignNewKey()
    {
        using (RSA rsa = RSA.Create(2048))
        {
            _privateKey = rsa.ExportParameters(true);
            _publicKey = rsa.ExportParameters(false);
        }
    }

    private static string ExportPublicKey()
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(_publicKey);
            return rsa.ToXmlString(false);
        }
    }

    private static string ExportPrivateKey()
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(_privateKey);
            return rsa.ToXmlString(true);
        }
    }

    private static byte[] SignData(string data)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(_privateKey);
            var dataBytes = Encoding.UTF8.GetBytes(data);
            return rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}
