using System.Text.RegularExpressions;

namespace CoreIRCLib.Definitions {
    public class Hostmask {
        private readonly string nickname, ident, hostname;

        public Hostmask(string nickname, string ident, string hostname) {
            this.nickname = nickname;
            this.ident = ident;
            this.hostname = hostname;
        }

        public Hostmask(string hostmask) {
            var result = Regex.Match(hostmask, @"(?<nickname>\w+?)!(?<ident>[\d\w]+?)@(?<hostname>[\w\d-\.]+)");
            
            nickname = result.Groups["nickname"].Value;
            ident = result.Groups["ident"].Value;
            hostname = result.Groups["hostname"].Value;
            
        }

        public string Nickname => nickname;
        public string Ident => ident;
        public string Hostname => hostname;

        public override string ToString() {
            return $"{nickname}!{ident}@{hostname}";
        }
    }
}