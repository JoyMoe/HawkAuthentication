using System;
using System.Net.Http;
using HawkAuthentication;
using HawkAuthentication.Client;

namespace ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage
                {
                    Method = HttpMethod.Get,
                    RequestUri = new Uri("http://localhost:5000/api/client")
                };

                request = new HawkRequestSigner(new HawkCredential
                {
                    KeyId = "dh37fgj492je", Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"
                }).SignAsync(request).Result;

                var result = client.SendAsync(request).Result;
                Console.WriteLine(result.Content.ReadAsStringAsync().Result);
            }
        }
    }
}
