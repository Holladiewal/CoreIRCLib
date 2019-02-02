using System;
using CoreIRCLib.Definitions;

namespace CoreIRCLib.util {
    public class Events {
        public class RawMessageEventArgs : EventArgs {
            public RawMessageEventArgs(string message, Connection connection) {
                Message = message;
                Connection = connection;
            }

            public string Message { get; }

            public Connection Connection { get; }
        }
        
        public class MessageEventArgs : EventArgs {
            private readonly Message message;

            public MessageEventArgs(Message message) {
                this.message = message;
            }

            public Message GetMessage() {
                return message;
            }
        }
        
        public class StringEventArgs : EventArgs {
            public StringEventArgs(string String) {
                this.String = String;
            }

            public string String { get; }
        }
        
        public class ModeChangeEventArgs : EventArgs {
            public ModeChangeEventArgs(Hostmask actor, IRCObject target, string changes) {
                Actor = actor;
                Target = target;
                Changes = changes;
            }

            public Hostmask Actor { get; }

            public IRCObject Target { get; }

            public string Changes { get; }
        }
        
        public static event EventHandler<MessageEventArgs> Message;
        public static event EventHandler<MessageEventArgs> Notice;
        public static event EventHandler<RawMessageEventArgs> RawMessage;
        public static event EventHandler<ModeChangeEventArgs> ModeChange;
        public static event EventHandler<StringEventArgs> CapAckEvent;
        public static event EventHandler<StringEventArgs> CapNakEvent;
        public static event EventHandler<StringEventArgs> CapLsEvent;

        
        // Invoking Functions
        public void OnMessage(MessageEventArgs args) {
            Message?.Invoke(this, args);
        }  
        
        public void OnNotice(MessageEventArgs args) {
            Notice?.Invoke(this, args);
        }

        public void OnRawMessage(RawMessageEventArgs args) {
            RawMessage?.Invoke(this, args);
        }

        public void OnModeChangeEvent(ModeChangeEventArgs args) {
            ModeChange?.Invoke(this, args);
        }
        
        public void OnCapAckEvent(StringEventArgs args) {
            CapAckEvent?.Invoke(this, args);
        }
        
        public void OnCapNakEvent(StringEventArgs args) {
            CapNakEvent?.Invoke(this, args);
        }
        
        public void OnCapLsEvent(StringEventArgs args) {
            CapLsEvent?.Invoke(this, args);
        }
    }
}