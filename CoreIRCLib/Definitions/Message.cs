namespace CoreIRCLib.Definitions {
    public class Message {
        public readonly Hostmask hostmask;
        public readonly string target;
        public readonly string message;

        public Message(Hostmask hostmask, string target, string message) {
            this.hostmask = hostmask;
            this.target = target;
            this.message = message;
        }
        
        
    }
}