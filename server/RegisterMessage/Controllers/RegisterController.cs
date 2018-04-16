using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

using RegisterMessage.Models;
using RegisterMessage.Helpers;
using System.IO;

namespace RegisterMessage.Controllers
{
    public class RegisterController : ApiController
    {
        private const string EXPECTED_MESSAGE = "How is the bacon?";
        private const string PFX_PATH = @"certs\DemoCert.pfx";
        private const string PFX_DEMO_KEY = "bd8d04b8aaa1f9c95c5629a1e995e2db";

        [HttpGet]
        [System.Web.Mvc.Route("registerbaconmessage")]
        public SimpleMessage RegisterBaconMessage()
        {
            return new SimpleMessage() { };
        }

        [HttpPost]
        [System.Web.Mvc.Route("registerbaconmessage")]
        public SimpleMessage RegisterBaconMessage(SimpleMessage message)
        {
            try
            {
                var simplerSigner = new SimpleRSADigitalSigner(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, PFX_PATH), PFX_DEMO_KEY);

                //Get the original message.
                string plainTextMessage = simplerSigner.Decrypt(message.Payload);
                string returnPlainTextMessage = "No registration.";

                //Verify that the signature is correct.
                if (simplerSigner.VerifySignature(plainTextMessage, message.Signature))
                {
                    //Verify the message is what we expect.
                    if (plainTextMessage.Equals(EXPECTED_MESSAGE))
                    {
                        returnPlainTextMessage = "It is sizzling in the pan!";
                    }
                }
                //END OF if (digitalSigning.VerifySignature(plainTextMessage, message.Signature))...

                return new SimpleMessage()
                {
                    Payload = simplerSigner.EncryptAsBase64String(returnPlainTextMessage),
                    Signature = simplerSigner.SignMessageAsBase64String(returnPlainTextMessage)
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }

            throw new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
        }
    }
}
