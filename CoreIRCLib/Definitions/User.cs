using System;
using System.Collections.Generic;

namespace CoreIRCLib.Definitions {
    public class User : IRCObject {
        private Hostmask _hostmask;
        private List<char> _modes = new List<char>();
        private readonly Guid _internalUUID;

        public User(Hostmask hostmask, string modeString = "") {
            _hostmask = hostmask;
            _internalUUID = Guid.NewGuid();
            bool? add = null;
            foreach (var chr in modeString) {
                switch (chr) {
                    case '-':
                        add = false; continue;
                    case '+':
                        add = true; continue;
                    default:
                        if (add != null && (bool) add) AddMode(chr);
                        if (add != null && !(bool) add) RemoveMode(chr);
                        continue;
                }
            }
            
            UserCache.PutUser(this);
        }
        
        private User(Hostmask hostmask, string modeString, Guid internalUuid) : this(hostmask, modeString) {
            _internalUUID = internalUuid;
        } 

        public Hostmask GetHostmask() {
            return _hostmask;
        }

        public List<char> GetModes() {
            return _modes;
        }

        public string GetModeString() {
            var tmpString = "";
            
            foreach (var chr in _modes) {
                tmpString += chr;
            }

            return tmpString;
        }

        public void AddMode(char modeChar) {
            if (!_modes.Contains(modeChar)) _modes.Add(modeChar);
        }

        public void RemoveMode(char modeChar) {
            if (_modes.Contains(modeChar)) _modes.Remove(modeChar);
        }

        public override bool IsChannel() {
            return false;
        }

        public override bool Equals(object obj) {
            if (obj == null) return false;
            var other = (User) obj;
            return other._hostmask == _hostmask && other._modes == _modes;
        }

        public override int GetHashCode() {
            return int.Parse(_internalUUID.ToString().Replace("-", ""));
        }

        public User Copy() {
            return new User(GetHostmask(), GetModeString(), _internalUUID);
        }
    }
    
    
}