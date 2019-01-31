using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using SInnovations.LetsEncrypt.Clients;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{

    public class CloudFlareDNSClient : IDnsClient
    {



     
        private readonly ICloudFlareZoneService zoneService;
        private readonly KeyVaultSecretManager keyVaultSecretManager;


        //private readonly ICloudFlareZoneService zoneService;
        private readonly HttpClient http;
       // private readonly KeyVaultOptions secrets;
      
        public CloudFlareDNSClient(HttpClient http,  ICloudFlareZoneService zoneService, KeyVaultSecretManager keyVaultSecretManager)
        {
            this.zoneService = zoneService ?? throw new ArgumentNullException(nameof(zoneService));
            this.keyVaultSecretManager = keyVaultSecretManager ?? throw new ArgumentNullException(nameof(keyVaultSecretManager));
            this.http = http ?? throw new ArgumentNullException(nameof(http));
            
            // this.zoneService = cloudFlareZoneService;


           
        }
        public async Task EnsureTxtRecordCreatedAsync(string dnsIdentifier, string recordName, string recordValue)
        {
            
        

            //  var zoneService = ServiceProxy.Create<ICloudFlareZoneService>(new Uri($"{codePackageActivationContext.ApplicationName}/{nameof(GatewayManagementService)}"), dnsIdentifier.ToPartitionHashFunction());

            var zone = await zoneService.GetZoneIdAsync(dnsIdentifier); //  "ac1d153353eebc8508f7bb31ef1ab46c";

            if (!string.IsNullOrEmpty(zone))
            {
                var (authEmail, authKey) = await GetCloudFlareCredentialsAsync(zone);

                var get = new HttpRequestMessage(HttpMethod.Get, $"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records?type=TXT&name={recordName}.{dnsIdentifier}");
                get.Headers.Add("X-Auth-Email", authEmail);
                get.Headers.Add("X-Auth-Key", authKey);
                var result = await http.SendAsync(get);
                var resultdata = JToken.Parse(await result.Content.ReadAsStringAsync());
                var id = resultdata.SelectToken("$.result[0].id")?.ToString();




                var post = new HttpRequestMessage(string.IsNullOrEmpty(id) ? HttpMethod.Post : HttpMethod.Put,
                    $"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records{(string.IsNullOrEmpty(id) ? "" : $"/{id}")}");
                post.Headers.Add("X-Auth-Email", authEmail);
                post.Headers.Add("X-Auth-Key", authKey);
                post.Content = new StringContent(
                    JToken.FromObject(new
                    {
                        type = "TXT",
                        name = recordName,
                        content = recordValue
                    }).ToString(), Encoding.UTF8, "application/json");

                var respons = await http.SendAsync(post);

                await Task.Delay(30000);
            }
            //else
            //{
            //    await dnsfallback.EnsureTxtRecordCreatedAsync(dnsIdentifier, recordName, recordValue);
            //}

        }

        private async Task<(string,string)> GetCloudFlareCredentialsAsync(string zone)
        {
           
            var key = await keyVaultSecretManager.GetSecretAsync("CloudFlare-"+zone) ??
                await keyVaultSecretManager.GetSecretAsync("CloudFlare");

         //   var key = secrets.CloudFlare;
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("Cloudflare credentials are not configured");
            }
           
            return (key.Substring(0, key.IndexOf(":")), key.Substring(key.IndexOf(":") + 1));
        }

        public async Task ClearTxtRecordAsync(string dnsIdentifier, string recordName, string recordValue)
        {
            var zone = await zoneService.GetZoneIdAsync(dnsIdentifier);
            if (!string.IsNullOrEmpty(zone))
            {
                var (authEmail, authKey) = await GetCloudFlareCredentialsAsync(zone);


                var get = new HttpRequestMessage(HttpMethod.Get, $"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records?type=TXT&name={recordName}.{dnsIdentifier}");
                get.Headers.Add("X-Auth-Email", authEmail);
                get.Headers.Add("X-Auth-Key", authKey);
                var result = await http.SendAsync(get);
                var resultdata = JToken.Parse(await result.Content.ReadAsStringAsync());
                var id = resultdata.SelectToken("$.result[0].id")?.ToString();
                if (!string.IsNullOrEmpty(id))
                {
                    var delete = new HttpRequestMessage(HttpMethod.Delete, $"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/"+id);
                    delete.Headers.Add("X-Auth-Email", authEmail);
                    delete.Headers.Add("X-Auth-Key", authKey);
                    await http.SendAsync(delete);
                }
            }
        }
    }










}
