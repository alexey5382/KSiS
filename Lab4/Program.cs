using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Proxy
{
    class Program
    {
        static string ProxyIp = "127.0.0.2";
        static int ProxyPort = 9000;
        static string path = "blacklist.txt";


        static List<string> Blacklist = new List<string>();

        static async Task Main(string[] args)
        {
            


            Console.WriteLine($"Запуск прокси-сервера: {ProxyIp}:{ProxyPort}...");

            IPAddress ipAddress = IPAddress.Parse(ProxyIp);
            TcpListener listener = new TcpListener(ipAddress, ProxyPort);
            listener.Start();

            Console.WriteLine("Прокси-сервер запущен.\n");

            while (true)
            {
                TcpClient browserClient = await listener.AcceptTcpClientAsync();

                _ = Task.Run(() => HandleClientAsync(browserClient));
            }
        }

        static async Task HandleClientAsync(TcpClient browserClient)
        {
            try
            {
                using (browserClient)
                using (NetworkStream browserStream = browserClient.GetStream())
                {
                    byte[] buffer = new byte[8192];
                    int bytesRead = await browserStream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0) return;

                    string requestString = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                    string[] lines = requestString.Split(new[] { "\r\n" }, StringSplitOptions.None);
                    if (lines.Length == 0) return;

                    string requestLine = lines[0];
                    string[] requestParts = requestLine.Split(' ');
                    if (requestParts.Length < 3) return;

                    string method = requestParts[0];
                    string fullUrl = requestParts[1];
                    string httpVersion = requestParts[2];

                    Uri uri = new Uri(fullUrl);
                    string host = uri.Host;
                    int port = uri.Port;
                    string pathAndQuery = uri.PathAndQuery;
                    if (File.Exists(path))
                    {
                        Blacklist = File.ReadAllLines(path).ToList();
                    }
                    if (Blacklist.Any(b => host.Contains(b, StringComparison.OrdinalIgnoreCase)))
                    {
                        SendBlockedResponse(browserStream, fullUrl);
                        Console.WriteLine($"{fullUrl} - 403 Forbidden");
                        return;
                    }

                    string newRequestLine = $"{method} {pathAndQuery} {httpVersion}";
                    string modifiedRequest = requestString.Replace(requestLine, newRequestLine);
                    byte[] modifiedRequestBytes = Encoding.ASCII.GetBytes(modifiedRequest);

                    using (TcpClient destinationClient = new TcpClient())
                    {
                        await destinationClient.ConnectAsync(host, port);
                        using (NetworkStream destinationStream = destinationClient.GetStream())
                        {

                            await destinationStream.WriteAsync(modifiedRequestBytes, 0, modifiedRequestBytes.Length);

                            Task serverToBrowser = TransferAndLogResponse(destinationStream, browserStream, fullUrl);

                            Task browserToServer = browserStream.CopyToAsync(destinationStream);

                            await Task.WhenAny(serverToBrowser, browserToServer);
                        }
                    }
                }
            }
            catch (Exception)
            {

            }
        }

        static async Task TransferAndLogResponse(NetworkStream serverStream, NetworkStream browserStream, string fullUrl)
        {
            byte[] buffer = new byte[8192];
            bool isFirstChunk = true;
            int bytesRead;

            while ((bytesRead = await serverStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                if (isFirstChunk)
                {
                    string responseText = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                    // Обновленное регулярное выражение: 
                    // Ищет "HTTP/1.1 " и затем захватывает всё до конца текущей строки
                    Match match = Regex.Match(responseText, @"^HTTP/\d\.\d\s+([^\r\n]+)");

                    // Если совпадение найдено, берем захваченный текст (например, "404 Not Found")
                    string statusString = match.Success ? match.Groups[1].Value.Trim() : "???";

                    Console.WriteLine($"{fullUrl} - {statusString}");
                    isFirstChunk = false;
                }

                await browserStream.WriteAsync(buffer, 0, bytesRead);
            }
        }

        static void SendBlockedResponse(NetworkStream stream, string url)
        {
            string html = $@"<html>
                            <head><title>Access Denied</title></head>
                            <body>
                                <h1>403 Forbidden</h1>
                                <p>Доступ к запрашиваемому ресурсу заблокирован прокси-сервером.</p>
                                <p>Заблокированный URL: <b>{url}</b></p>
                            </body>
                            </html>";

            string header = "HTTP/1.1 403 Forbidden\r\n" +
                            "Content-Type: text/html; charset=utf-8\r\n" +
                            $"Content-Length: {Encoding.UTF8.GetByteCount(html)}\r\n" +
                            "Connection: close\r\n\r\n";

            byte[] responseBytes = Encoding.UTF8.GetBytes(header + html);
            stream.Write(responseBytes, 0, responseBytes.Length);
        }
    }
}