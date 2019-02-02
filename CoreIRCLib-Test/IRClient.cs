using System;
using CoreIRCLib;
using CoreIRCLib.util;

namespace CoreIRCLib_Test
{
    // ReSharper disable once InconsistentNaming
    
    public class IRClient {
        public static void Main(string[] args) {
            var client = new Client("whydoyouhate.me", 6697, "IRCLibTest", "IRCLibTest", "gnarr", "I am an IRCLib", true, true, "EXTERNAL",  @"C:\RiderProjects\CoreIRCLib\CoreIRCLib-Test\");
            
            Events.RawMessage += OnRawMessage;
            Events.Message += OnMessage;

        }

        private static void OnRawMessage(object o, Events.RawMessageEventArgs args) {
            var message = args.Message;

            if (message.Replace("\0", "").Replace("\n", "").Replace("\r", "").Trim().Length <= 0) return;
            
            // Console.WriteLine(message.Trim());
        }

        private static void OnMessage(object o, Events.MessageEventArgs args) {
            var message = args.GetMessage();
            // Console.WriteLine("Received parsed Message from " + message.hostmask.ToString() + " in " + message.target + ": " + message.message);
        }
    }
    
}