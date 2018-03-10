using System;
using System.Collections.Generic;
using System.Fabric;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.AzureKeyVault;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Unity;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SInnovations.DnsMadeEasy;
using SInnovations.LetsEncrypt;
using SInnovations.LetsEncrypt.Clients;
using SInnovations.LetsEncrypt.DnsMadeEasyManager;
using SInnovations.LetsEncrypt.Services;
using SInnovations.LetsEncrypt.Services.Defaults;
using SInnovations.LetsEncrypt.Stores;
using SInnovations.LetsEncrypt.Stores.Defaults;
using SInnovations.ServiceFabric.Storage.Configuration;
using SInnovations.ServiceFabric.Unity;
using Certes;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{


    public class CloudFlareZoneService
    {
        private readonly Dictionary<string, string> _zones = new Dictionary<string, string>();
        public Task<string> GetZoneIdAsync(string dnsIdentifier)
        {
            var domain = string.Join(".", dnsIdentifier.Split(".").TakeLast(2)).ToLower();
            if (_zones.ContainsKey(domain))
                return Task.FromResult(_zones[dnsIdentifier]);
            return Task.FromResult(string.Empty);
        }

        public Task UpdateZoneIdAsync(string v1, string v2)
        {
            _zones[v1] = v2;
            return Task.CompletedTask;
        }
    }
    public class CloudFlareDNSClient : IDnsClient
    {



        private LetsEncryptDnsMadeEasyManager dnsfallback;
        private readonly CloudFlareZoneService zoneService;
        private readonly HttpClient http;
        private readonly string authKey;
        private readonly string authEmail;
        public CloudFlareDNSClient(HttpClient http, LetsEncryptDnsMadeEasyManager dnsfallback, IOptions<KeyVaultOptions> secrets, CloudFlareZoneService cloudFlareZoneService)
        {
            this.dnsfallback = dnsfallback;
            this.http = http;
            this.zoneService = cloudFlareZoneService;
            var key = secrets.Value.CloudFlare;

            this.authEmail = key.Substring(0, key.IndexOf(":"));
            this.authKey = key.Substring(key.IndexOf(":") + 1);
        }
        public async Task EnsureTxtRecordCreatedAsync(string dnsIdentifier, string recordName, string recordValue)
        {



            var zone = await zoneService.GetZoneIdAsync(dnsIdentifier); //  "ac1d153353eebc8508f7bb31ef1ab46c";
            if (!string.IsNullOrEmpty(zone))
            {
                var get = new HttpRequestMessage(HttpMethod.Get, $"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records?type=TXT&name={recordName}");
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
            else
            {
                await dnsfallback.EnsureTxtRecordCreatedAsync(dnsIdentifier, recordName, recordValue);
            }

        }
    }




    public static class DsnExtensions
    {
        public static IUnityContainer WithLetsEncryptService(this IUnityContainer container, LetsEncryptServiceOptions options)
        {
            container.RegisterInstance(options);
            container.AddScoped<IRS256SignerStore, InMemoryRS256SignerStore>();
            container.AddScoped<IRS256SignerService, DefaultRS256SignerService>();
            container.AddScoped<IAcmeClientService<AcmeContext>, CertesAcmeClientService>();
            container.AddScoped<IAcmeRegistrationStore, InMemoryAcmeRegistrationStore>();
            container.RegisterType<CertesChallengeService>(new global::Unity.Lifetime.HierarchicalLifetimeManager());
            container.AddScoped<ILetsEncryptChallengeService<AcmeContext>, CertesChallengeService>();
            container.AddScoped<IOrders, CertesChallengeService>();

            container.RegisterInstance(new CloudFlareZoneService());
            container.AddScoped<IDnsClient, CloudFlareDNSClient>();

            container.AddScoped<DnsMadeEasyClientCredetials, DnsMadeEasyOptions>();
            container.AddScoped<LetsEncryptService<AcmeClient>>();

            return container;
        }
    }



    public class DnsMadeEasyOptions : DnsMadeEasyClientCredetials
    {
        public DnsMadeEasyOptions(IOptions<KeyVaultOptions> keyvault)
        {
            var parts = keyvault.Value.DnsMadeEasyCredentials.Split(':');
            this.ApiKey = parts[0];
            this.ApiSecret = parts[1];
        }
    }

    public class KeyVaultOptions
    {
        public string DnsMadeEasyCredentials { get; set; }
        public string CloudFlare { get; set; }
    }










}
