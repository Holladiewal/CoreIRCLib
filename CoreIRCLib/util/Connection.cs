using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using OpenSSL.SSL;
using SslProtocols = System.Security.Authentication.SslProtocols;
using SslStream = System.Net.Security.SslStream;

namespace CoreIRCLib.util {
    public class Connection {

        Socket socket;
        private Stream NetworkStream;
        private string oldRawResponse = "";
        // ReSharper disable once InconsistentNaming
        private readonly Events Events = new Events();
        private readonly int port;
        private readonly IPAddress addr;
        internal bool pinged = false, ssl;
        private Queue<string> sendQueue = new Queue<string>();

        private Thread queueClearer = new Thread(conn_obj => {
            var conn = (Connection) conn_obj;
            while (true) {
                if (conn.pinged) {
                    while (conn.sendQueue.Count > 0) {
                        conn._send(conn.sendQueue.Dequeue());
                    }
                    break;
                }
            }

        });
        
        public Connection(int port, string addr, bool ssl) : this(port, IPAddress.Parse(addr), ssl) { }

        public Connection(int port, IPAddress addr, bool ssl, string certpath = "") {
            socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            this.port = port;
            this.addr = addr;
            this.ssl = ssl;
            Connect(certpath);
        }

        private void Connect(string certpath) {
            socket.Connect(addr, port);
            while (!socket.Connected) { }
            NetworkStream = new NetworkStream(socket);

            NetworkStream = ssl ? new SslStream(NetworkStream, false, (sender, certificate, chain, errors) => true) : NetworkStream;

            if (ssl) {
                var stream = (SslStream) NetworkStream;
                var clientcert = new X509CertificateCollection();
                if (certpath.Length > 0) {
                    if (!File.Exists(certpath + "puttygen.pem")) {
                        Console.WriteLine("Generating cert.");
                        var cert = CertHelper.genCert();
                        CertHelper.saveCert(cert);
                    }

                    clientcert.Add(CertHelper.loadCert(certpath + "IRCLib.pfx", "irclib"));
                }
                
                stream.AuthenticateAsClient("irc.whydoyouhate.me", clientcert, SslProtocols.Tls, true);


            }
            
            Thread receiverThread = new Thread(o => {
                while (true) {
                    Receive();
                    Thread.Sleep(500);
                }
                // ReSharper disable once FunctionNeverReturns
            });
            receiverThread.Start();
            queueClearer.Start(this);
                        
        }


        
        public void Receive() {
            var buffer = new byte[4096];
            var actuallyRead = NetworkStream.Read(buffer, 0, 4096);
            
            var rawResponse = oldRawResponse + Encoding.UTF8.GetString(buffer).Replace("\0", "");
            var splitResponse = rawResponse.Replace("\r", "").Split('\n');
            if (!splitResponse.Last().EndsWith("\n")) {
                oldRawResponse = splitResponse.Last();
                splitResponse[splitResponse.Length - 1] = "";
            }
            else {
                oldRawResponse = "";
            }
            
            foreach (var str in splitResponse.Except(new []{""})) {
                Console.WriteLine(str);
                Events.OnRawMessage(new Events.RawMessageEventArgs(str, this));
            }
            
        }

        public void Send(string message) {
            if (message == null) return;
            
            if (pinged) {
                _send(message);
            }
            else {
                if (message.StartsWith("NICK") || message.StartsWith("USER") || message.StartsWith("PASS") ||
                    message.StartsWith("PONG") || message.StartsWith("CAP") || message.StartsWith("AUTHENTICATE")) {
                    _send(message);
                    return;
                }
                sendQueue.Enqueue(message);
            }
        }

        private void _send(string message) {
            message = message.Trim('\r', '\n') + "\r\n";
            var sendBuffer = Encoding.UTF8.GetBytes(message);
            NetworkStream.Write(sendBuffer, 0, sendBuffer.Length);
        }
    }
}