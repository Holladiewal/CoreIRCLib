using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using CoreIRCLib.Definitions;
using CoreIRCLib.util;
using Org.BouncyCastle.Crypto.Parameters;

//using System.Runtime.Remoting.Channels;

namespace CoreIRCLib {
    public class Client {
        private readonly string _nick;
        private static readonly Events Events = new Events();
        private readonly List<string> _acknowledgedCapabilities = new List<string>();
        private readonly List<string> _supportedCapabilities = new List<string>();
        private bool _authInProgress;

        public Client(string hostname, int port, string nick, string username, string password, string realname,
                      bool ssl, bool sasl = false, string saslMechanism = "", string certpath = "") {
            _nick = nick;
            
            var ip = Dns.GetHostEntry(hostname).AddressList[0];
            var connection = new Connection(port, ip, ssl, certpath);
            
            Events.RawMessage += ParseRawMessage;
            
            if (!String.IsNullOrEmpty(password.Trim()) && !sasl)
                connection.Send("PASS " + password);
            connection.Send("NICK " + _nick);
            connection.Send("USER " + username + " 0 * :" + realname);

            connection.Send("CAP LS 302");
            
            if (sasl) {
                while (_supportedCapabilities.Count < 1) ;
                if (_supportedCapabilities.Contains("sasl"))
                    connection.Send("CAP REQ :sasl");
                else return;
                while (!_acknowledgedCapabilities.Contains("sasl")) {
                    var capstring = "";
                    _acknowledgedCapabilities.ForEach(strin => capstring += $"{strin} ");
                    //Console.WriteLine($"Acknowledged Capabilities while waiting for sasl: {capstring}");
                }
                connection.Send($"AUTHENTICATE {saslMechanism}");
                while (!_authInProgress) ;
                switch (saslMechanism) {
                    case "EXTERNAL": {
                        connection.Send("AUTHENTICATE +");
                        break;
                    }
                    
                    case "PLAIN": {
                        var bytes = Encoding.UTF8.GetBytes($"{username}\0{username}\0{password}");
                        var setsNeeded = (int) Math.Ceiling(bytes.Length / 400D);
                        var byteSets = new byte[setsNeeded][];
                        for (var i = 0; i < setsNeeded; i++) {
                            byteSets[i] = new byte[398];
                            var sizeRemainig = bytes.Length - 398 * Math.Max(i - 1, 0);
                            Array.Copy(bytes, i * 397, byteSets[i], 0, sizeRemainig);
                        }

                        for (var i = 0; i < byteSets.Length; i++) {
                            var byteSet = byteSets[i];
                            connection.Send(i == byteSets.Length - 1
                                ? $"AUTHENTICATE {Convert.ToBase64String(bytes)} +"
                                : $"AUTHENTICATE {Convert.ToBase64String(bytes)}"
                            );
                        }
                        
                        
                        break;
                    }
                    
                    default: throw new NotSupportedException($"SASL MECHANISM '{saslMechanism}' is not supported'");
                }
            }
            connection.Send("CAP END");
            
            // connection.Send("JOIN #testchannel");


        }

        public void ParseRawMessage(object o, Events.RawMessageEventArgs args) {
            var message = args.Message;
            if (message[0] != ':') {
                var splitMessage = message.Split(new []{':'}, 2);
                // ReSharper disable once InvertIf
                if (splitMessage[0].Contains("PING")) {
                    args.Connection.Send("PONG :" + splitMessage[1]);
                    args.Connection.pinged = true;
                }

                if (splitMessage[0].StartsWith("AUTHENTICATE")) {
                    if (splitMessage[0] == "AUTHENTICATE +") _authInProgress = true;
                }
            }
            else {
                var param = new List<string>();
                message = message.Remove(0, 1);
                var meta = message.Split(new []{':'}, 2)[0];

                var splitMeta = meta.Split(new []{' '}, 4);
                
                param.AddRange(meta.Split(' '));
                param.Add(message.Split(new []{':'}, 2)[1]);
                
                var actor = splitMeta[0];
                var action = splitMeta[1];
                var target = splitMeta[2];
                var remainder = splitMeta.Length > 3 ? splitMeta[3] : ""; 

                if (Regex.IsMatch(action, @"^\d+$")) {
                    // is a numeric
                    
                    ParseNumeric(message, remainder, action, actor, target);
                }
                else {
                    // Not a numeric

                    ParseNonNumeric(message, remainder, action, actor, target);
                }
            }
        }

        internal void ParseNonNumeric(string message, string remainder, string action, string actor, string target) {
            var data = message.Contains(":") ? message.Split(new[] {':'}, 2)[1] : remainder;

            switch (action) {
                case "PRIVMSG": {
                    Events.OnMessage(new Events.MessageEventArgs(new Message(new Hostmask(actor), target, data)));
                    break;
                }

                case "MODE": {
                    var senderHostmask =
                        actor.Contains("!") ? new Hostmask(actor) : new Hostmask("", "", actor);
                    IRCObject targetObject = target.StartsWith("#")
                        ? (IRCObject) ChannelCache.ByName(target.Remove(0, 1))
                        : UserCache.ByNick(target);
                    Events.OnModeChangeEvent(new Events.ModeChangeEventArgs(senderHostmask, targetObject, data));
                    break;
                }

                case "JOIN": {
                    if (actor.Remove(actor.IndexOf("!", StringComparison.Ordinal)) == _nick) {
                        // WE joined a channel
                        Console.WriteLine($"target string is: {data}");
                        ChannelCache.PutChannel(new Channel(data.Remove(0, 1), ""));
                    } else {
                        // somebody else joined a channel we are in
                        var usr = UserCache.ByHostmask(new Hostmask(actor));
                        usr = usr ?? new User(new Hostmask(actor));
                        ChannelCache.ByName(data.Remove(0, 1)).AddUser(usr);
                    }

                    break;
                }

                case "PART": {
                    if (actor.Remove(actor.IndexOf("!", StringComparison.Ordinal)) == _nick) {
                        // WE left a channel
                        ChannelCache.RemoveChannelByName(data.Remove(0, 1));
                    } else {
                        // somebody else left a channel we are in
                        var usr = UserCache.ByHostmask(new Hostmask(actor));
                        usr = usr ?? new User(new Hostmask(actor));
                        ChannelCache.ByName(data.Remove(0, 1)).RemoveUser(usr);
                    }

                    break;
                }

                case "NOTICE": {
                    Events.OnNotice(new Events.MessageEventArgs(new Message(new Hostmask(actor), target, data)));
                    break;
                }

                case "CAP": {
                    switch (remainder.Split(' ')[0]) {
                        case "ACK":
                            // foreach (var str in data.Split(' ')) { _acknowledgedCapabilities.Add(str); }
                            _acknowledgedCapabilities.AddRange(data.Split(' '));
                            Events.OnCapAckEvent(new Events.StringEventArgs(data));

                            var capstring_ACK = "";
                            _acknowledgedCapabilities.ForEach(strin => capstring_ACK += $"{strin} ");
                            Console.WriteLine($"Caps acknowledged: {capstring_ACK}");

                            break;
                        case "NAK":
                            Events.OnCapNakEvent(new Events.StringEventArgs(data));
                            break;

                        case "LS":
                            Console.WriteLine("INCOMING CAP LIST!");
                            _supportedCapabilities.AddRange(data.Split(' '));
                            if (!(remainder.Length > 2 && remainder.Split(' ')[1] == "*")) {
                                var capstring = "";
                                _supportedCapabilities.ForEach(strin => capstring += $"{strin} ");

                                Events.OnCapLsEvent(new Events.StringEventArgs(capstring));
                                Console.WriteLine($"END OF CAP LIST, SUPPORTED CAPS: {capstring}");
                            }

                            break;
                    }

                    break;
                }
            }
        }

        internal void ParseNumeric(string message, string remainder, string numeric, string actor, string target) {
            switch (numeric[0]) {
                case '0': {
                    ParserNumeric0xx(message, remainder, numeric, actor, target);
                    break;
                }
                case '2': {
                    ParserNumeric2xx(message, remainder, numeric, actor, target);
                    break;
                }
                case '3': {
                    ParserNumeric3xx(message, remainder, numeric, actor, target);
                    break;
                }
                case '4': {
                    ParserNumeric4xx(message, remainder, numeric, actor, target);
                    break;
                }
                case '5': {
                    ParserNumeric5xx(message, remainder, numeric, actor, target);
                    break;
                }
                case '6': {
                    ParserNumeric6xx(message, remainder, numeric, actor, target);
                    break;
                }
                case '7': {
                    ParserNumeric7xx(message, remainder, numeric, actor, target);
                    break;
                }
                case '9': {
                    ParserNumeric9xx(message, remainder, numeric, actor, target);
                    break;
                }
            }
        }

        private void ParserNumeric0xx(string message, string remainder, string numeric, string actor, string target) {
            switch (numeric) {
                case "001":
                    // RPL WELCOME, welcome message, shall not be parsed
                    break;
                
                case "002":
                    //RPL YOURHOST, info about the server and server software. Do not parse.
                    break;
                
                case "003":
                    //RPL CREATED, creation time of the server. Do not parse.
                    break;
                
                case "004": 
                    //RPL_MYINFO, lot of server info data, parsable. use 005 instead, please.
                    break;

                case "005": {
                    //RPL_ISSUPPORT
                    break;
                }

                case "010": {
                    //RPL_BOUNCE
                    var hostname = target;
                    var port = message;
                    
                    break;
                }
            }
            
        }

        private void ParserNumeric2xx(string message, string remainder, string numeric, string actor, string target) {
            switch (numeric) {
                case "221": { break; }
                case "251": { break; }
                case "252": { break; }
                case "253": { break; }
                case "254": { break; }
                case "255": { break; }
                case "256": { break; }
                case "257": { break; }
                case "258": { break; }
                case "259": { break; }
                case "263": { break; }
                case "265": { break; }
                case "266": { break; }
                case "276": { break; }
            }
        }

        private void ParserNumeric3xx(string message, string remainder, string numeric, string actor, string target) {
            switch (numeric) {
                case "300": { break; }
                case "301": { break; }
                case "302": { break; }
                case "303": { break; }
                case "304": { break; }
                case "305": { break; }
                case "306": { break; }
                case "311": { break; }
                case "312": { break; }
                case "313": { break; }
                case "314": { break; }
                case "317": { break; }
                case "318": { break; }
                case "319": { break; }
                case "321": { break; }
                case "322": { break; }
                case "323": { break; }
                case "324": { break; }
                case "331": { break; }
                case "332": { break; }
                case "333": { break; }
                case "341": { break; }
                case "346": { break; }
                case "347": { break; }
                case "348": { break; }
                case "349": { break; }
                case "351": { break; }
                case "353": { break; }
                case "366": { break; }
                case "367": { break; }
                case "368": { break; }
                case "369": { break; }
                case "375": { break; }
                case "372": { break; }
                case "376": { break; }
                case "381": { break; }
                case "382": { break; }
            }
        }

        private void ParserNumeric4xx(string message, string remainder, string numeric, string actor, string target) {
            switch (numeric) {
                case "400": { break; }
                case "401": { break; }
                case "402": { break; }
                case "403": { break; }
                case "404": { break; }
                case "405": { break; }
                case "421": { break; }
                case "422": { break; }
                case "432": { break; }
                case "433": { break; }
                case "441": { break; }
                case "442": { break; }
                case "443": { break; }
                case "451": { break; }
                case "461": { break; }
                case "462": { break; }
                case "464": { break; }
                case "465": { break; }
                case "471": { break; }
                case "472": { break; }
                case "473": { break; }
                case "474": { break; }
                case "475": { break; }
                case "481": { break; }
                case "482": { break; }
                case "483": { break; }
                case "491": { break; }
            }
        }

        private void ParserNumeric5xx(string message, string remainder, string numeric, string actor, string target) {
            switch (numeric) {
                //Mode errors
                case "501": { break; }
                case "502": { break; }
            }
        }
        
        private void ParserNumeric6xx(string message, string remainder, string numeric, string actor, string target) {
            switch (numeric) {
                //Starttls
                case "670": { break; }
                case "691": { break; }
            }
        }
        private void ParserNumeric7xx(string message, string remainder, string numeric, string actor, string target) {
            switch (numeric) {
                case "723": { break; }
            }
        }
        
        private void ParserNumeric9xx(string message, string remainder, string numeric, string actor, string target) {
            //SASL
            switch (numeric) {
                case "900": { break; }
                case "901": { break; }
                case "902": { break; }
                case "903": { break; }
                case "904": { break; }
                case "905": { break; }
                case "906": { break; }
                case "907": { break; }
                case "908": { break; }
            }
        }
    }
}