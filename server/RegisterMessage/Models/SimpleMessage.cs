using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace RegisterMessage.Models
{
    public class SimpleMessage
    {
        public string Payload { get; set; }
        public string Signature { get; set; }

        public SimpleMessage()
        {
            Payload = string.Empty;
            Signature = string.Empty;
        }
    }
}