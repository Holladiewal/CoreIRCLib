using System.Collections.Generic;
using CoreIRCLib.Definitions;

namespace CoreIRCLib {
    public struct UserCache {
        private static List<User> _users = new List<User>();

        public static User ByHostmask(Hostmask hostmask) {
            return _users.Find(user => user.GetHostmask() == hostmask);
        }

        public static User ByNick(string nickname) {
            return _users.Find(user => user.GetHostmask().Nickname == nickname);
        }

        public static User ByHostname(string hostname) {
            return _users.Find(user => user.GetHostmask().Hostname == hostname);
        }

        public static void PutUser(User user) {
            if (!_users.Exists(User => Equals(User, user))) _users.Add(user); 
        }

    }
}