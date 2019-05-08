using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Bunq.Sdk.Context;
using Bunq.Sdk.Model.Generated.Endpoint;
using Bunq.Sdk.Security;
using Newtonsoft.Json;

namespace BunqSqkPsd2Runner
{
    class Program
    {
        private static void Main(string[] args)
        {
            var environmentType = ApiEnvironmentType.SANDBOX;
            var deviceDescription = "C# PSD2 test runner";
            var permittedIps = new List<string>();
            var redirectUri = "https://postman-echo.com/get";
            var certificateString = 
@"-----BEGIN CERTIFICATE-----
Please use the following command to generate a certificate for sandbox:

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=<YOUR COMPANY NAME> PISP AISP/C=NL'

Make sure to supply a company name or any other identifier so that we'll be able to assist you if you have any problems.

Replace that text with the contents of cert.pem

-----END CERTIFICATE-----";
            
            var privateKeyString = 
@"-----BEGIN PRIVATE KEY-----
Please use the command described above to get certificate and a private key.

Replace that text with the contents of key.pem

-----END PRIVATE KEY-----";
            
            var certificateChainString = 
@"-----BEGIN CERTIFICATE-----
MIID1zCCAr+gAwIBAgIBATANBgkqhkiG9w0BAQsFADB1MQswCQYDVQQGEwJOTDEW
MBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFtMRIwEAYD
VQQKEwlidW5xIGIudi4xDzANBgNVBAsTBkRldk9wczEVMBMGA1UEAxMMUFNEMiBU
ZXN0IENBMB4XDTE5MDIxODEzNDkwMFoXDTI5MDIxODEzNDkwMFowdTELMAkGA1UE
BhMCTkwxFjAUBgNVBAgTDU5vb3JkLUhvbGxhbmQxEjAQBgNVBAcTCUFtc3RlcmRh
bTESMBAGA1UEChMJYnVucSBiLnYuMQ8wDQYDVQQLEwZEZXZPcHMxFTATBgNVBAMT
DFBTRDIgVGVzdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALOv
zPl+uegBpnFhXsjuKs0ws00e+232wR9tvDqYBjGdOlYorw8CyrT+mr0HKO9lx7vg
xhJ3f+oonkZvBb+IehDmEsBbZ+vRtdjEWw3RTWVBT69jPcRQGE2e5qUuTJYVCONY
JsOQP8CoCHXa6+oUSmUyMZX/zNJhTvbLV9e/qpIWwWVrKzK0EEB5c71gITNgzOXG
+lIKJmOnvvJyWPCx02hIgQI3nVphDj8ydMEKuwTgBrFV5Lqkar3L6ngF7LgzjXPC
Nbf3JL/2Ccp0hYPb2MLVEpYba8/38eN6izjorJiwu+uGehOpj/RNcfv27iGyvXRY
FC2PfRP8ZP5CpoijJR8CAwEAAaNyMHAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU38gzLVi6UQYiNLXKIhwoklPnSYMwCwYDVR0PBAQDAgEGMBEGCWCGSAGG+EIB
AQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3
DQEBCwUAA4IBAQBt6HBrnSvEbUX514ab3Zepdct0QWVLzzEKFC8y9ARLWttyaRJ5
AhzCa4t8LJnyoYuEPHOKDIsqLzmJlwqBnsXPuMdWEd3vnFRgj1oL3vVqoJwrfqDp
S3jHshWopqMKtmzAO9Q3BWpk/lrqJTP1y/6057LtMGhwA6m0fDmvA+VuTrh9mgzw
FgWwmahVa08h1Cm5+vc1Phi8wVXi3R1NzmVUQFYOixSwifs8P0MstBfCFlBFQ47C
EvGEYvOBLlEiiaoMUT6aoYj+L8zHWXakSQFAzIzQFJn668q2ds6zx67P7wKFZ887
VJSv7sTqspxON1s1oFlkRXu5JihaVJcHmFAY
-----END CERTIFICATE-----";

            if (certificateString.Contains("Please"))
            {
                Console.WriteLine("Please generate a certificate and a private key and update the code.");
                Console.WriteLine();
                Console.WriteLine("Use the following command:");
                Console.WriteLine("openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=<YOUR COMPANY NAME> PISP AISP/C=NL'");
                return;
            }
            
            var certificatePublic = new X509Certificate2(Encoding.UTF8.GetBytes(certificateString));

            var keyPair = SecurityUtils.CreateKeyPairFromPrivateKeyFormattedString(
                privateKeyString);
            var certificate = certificatePublic.CopyWithPrivateKey(keyPair);

            var certificateChain = new X509Certificate2Collection();
            certificateChain.Import(Encoding.UTF8.GetBytes(
                certificateChainString
            ));

            var psd2ApiContext = ApiContext.CreateForPsd2(environmentType, certificate, certificateChain, 
                deviceDescription, permittedIps);
            BunqContext.LoadApiContext(psd2ApiContext);
            var allOauthClient = OauthClient.List();
            if (!allOauthClient.Value.Any())
            {
                OauthClient.Create("ACTIVE");
                allOauthClient = OauthClient.List();
            }

            var client = allOauthClient.Value.First();
            Debug.Assert(client.Id != null, "client.Id != null");
            if (OauthCallbackUrl.List(client.Id.Value).Value.All(ocu => ocu.Url != redirectUri))
            {
                OauthCallbackUrl.Create(client.Id.Value, redirectUri);
            }

            Console.WriteLine(JsonConvert.SerializeObject(client));

            Console.WriteLine("To continue, you'll need a user with an installed app. For sandbox it needs to be "+
                              "an android app downloadable from https://appstore.bunq.com/api/android/builds/bunq-android-sandbox-master.apk");
            Console.WriteLine("You can create a sandbox user using tinker, see links at https://www.bunq.com/developer");
            Console.WriteLine("Run UserOverview, that'll show the user's phone number and add some money to the account.");
            Console.WriteLine("You can then login in app with phone/email displayed by tinker script and login code 000000");
            Console.WriteLine("If the app tries to send a code to phone it's going to be 123456");
            Console.WriteLine("If the app tries to scan 4 fingers, any finger-like picture should be accepted");
            Console.WriteLine();
            Console.WriteLine("https://oauth.sandbox.bunq.com/auth?response_type=code&client_id=" + client.ClientId +
                              "&redirect_uri=" + redirectUri);
            Console.WriteLine();
            Console.WriteLine(
                "Please direct user to the above url. When you successfully authorized the code in the app," +
                "it'll redirect to the website with the code. Please input the code: \n");
            var code = Console.ReadLine();
            var tokenUrl = "https://api-oauth.sandbox.bunq.com/v1/token?grant_type=authorization_code&code=" + code +
                           "&redirect_uri=" + redirectUri + "&client_id=" + client.ClientId + "&client_secret=" +
                           client.Secret;
            var httpClient = new HttpClient();
            var tokenRequestResult = httpClient.PostAsync(tokenUrl, new StringContent("")).Result.Content
                .ReadAsStringAsync().Result;
            dynamic result = JsonConvert.DeserializeObject(
                tokenRequestResult
            );
            if (result.access_token != null)
            {
                string apiKey = result.access_token;

                var apiContext = ApiContext.Create(
                    environmentType, apiKey, deviceDescription, permittedIps);
                BunqContext.LoadApiContext(apiContext);
                Console.WriteLine(JsonConvert.SerializeObject(MonetaryAccount.List().Value.First()));
            }
            else
            {
                Console.WriteLine("Couldn't get token!");
                Console.WriteLine(tokenRequestResult);
            }
        }
    }
}