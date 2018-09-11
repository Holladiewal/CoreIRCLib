using System;
using System.Collections.Generic;

namespace CoreIRCLib.Definitions {   
    public class Channel : IRCObject {
        internal HashSet<char> spaceModes = new HashSet<char>{'v', 'b', 'h', 'o', 'q', 'I', 'e', 'a', 'l'};

        public string Name { get; }
        private List<string> _modes = new List<string>();
        public string Topic { get; }
        private List<User> _members = new List<User>();

        public Channel(string name, string topic, string modeString = "") {
            Name = name;
            Topic = topic;
            
            HandleModeString(modeString);
        }

        public void AddMode(string modeString) {
            if (modeString.StartsWith("+") || modeString.StartsWith("-")) throw new ArgumentException("AddMode's modestring should not contain '+' or '-' ");
                var param = modeString.Split(' ');
                for (var i = 0; i < param[0].Length; i++) {
                    var chr = param[0][i];
                    _modes.Add(spaceModes.Contains(chr) ? $"{chr} {param[i + 1]}" : $"{chr}");
                }
        }

        public void RemoveMode(string modeString) {
            if (modeString.StartsWith("+") || modeString.StartsWith("-")) throw new ArgumentException("RemoveMode's modestring should not contain '+' or '-' ");
            var param = modeString.Split(' ');
            for (var i = 0; i < param[0].Length; i++) {
                var chr = param[0][i];
                _modes.Remove(spaceModes.Contains(chr) ? $"{chr} {param[i + 1]}" : $"{chr}");
            }
        }

        public void HandleModeString(string modestring) {
            bool? add = null;
            string addString = "", remString = "";
            foreach (var chr in modestring) {
                switch (chr) {
                    case '-':
                        add = false; continue;
                    case '+':
                        add = true; continue;
                    default:
                        if (add != null && (bool) add) addString += chr;
                        if (add != null && !(bool) add) remString += chr;
                        continue;
                }
            }
            if (addString.Length > 0) AddMode(addString);
            if (remString.Length > 0) RemoveMode(remString);
        }

        public override bool IsChannel() {
            return true;
        }

        public void AddUser(User user) {
            if (!_members.Contains(user)) _members.Add(user);
        }

        public void RemoveUser(User user) {
            if (!_members.Exists(usr => usr.Equals(user))) _members.RemoveAll(usr => usr.Equals(user));
        }
    }
    
    
}