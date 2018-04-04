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
using Unity.Lifetime;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.Client;
using SInnovations.ServiceFabric.Gateway.Common.Actors;
using SInnovations.ServiceFabric.GatewayService.Actors;
using Microsoft.ServiceFabric.Services.Remoting.V2.FabricTransport.Client;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using Polly.Retry;
using Polly;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{

    public interface ICloudFlareZoneService : IService
    {
        //public CloudFlareZoneService()
        //{

        //}

        Task<string> GetZoneIdAsync(string dnsIdentifier);
        Task UpdateZoneIdAsync(string v1, string v2);
    }
    //public class CloudFlareZoneService : ICloudFlareZoneService
    //{
    //    public CloudFlareZoneService()
    //    {

    //    }
    //    private readonly Dictionary<string, string> _zones = new Dictionary<string, string>();
    //    public Task<string> GetZoneIdAsync(string dnsIdentifier)
    //    {
    //        var domain = string.Join(".", dnsIdentifier.Split(".").TakeLast(2)).ToLower();
    //        if (_zones.ContainsKey(domain))
    //            return Task.FromResult(_zones[dnsIdentifier]);
    //        return Task.FromResult(string.Empty);
    //    }

    //    public Task UpdateZoneIdAsync(string v1, string v2)
    //    {
    //        _zones[v1] = v2;
    //        return Task.CompletedTask;
    //    }
    //}
    public class GatewayManagementServiceClient
    {
        private readonly ICodePackageActivationContext codePackageActivationContext;

        public GatewayManagementServiceClient(ICodePackageActivationContext codePackageActivationContext)
        {
            this.codePackageActivationContext = codePackageActivationContext;
        }
        public static TimeSpan TimeoutSpan = TimeSpan.FromSeconds(30);

        public static RetryPolicy TimeOutRetry= Policy
              .Handle<TimeoutException>()
              .WaitAndRetryAsync(
                5, 
                retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)), 
                (exception, timeSpan, context) => {
                  // do something
                }
              );
        protected T GetProxy<T>(string partition) where T:IService => CreateProxyFactoryFabricTransport().CreateServiceProxy<T>(new Uri($"{codePackageActivationContext.ApplicationName}/{nameof(GatewayManagementService)}"), partition.ToPartitionHashFunction());

        public static T GetProxy<T>(string service,string partition) where T : IService => CreateProxyFactoryFabricTransport().CreateServiceProxy<T>(new Uri(service), partition.ToPartitionHashFunction());


        public static IServiceProxyFactory CreateProxyFactoryFabricTransport()
        {


            var settings = new FabricTransportRemotingSettings();

            settings.OperationTimeout = TimeSpan.FromMinutes(1);
            return new ServiceProxyFactory(
                (h) =>
                {
                    return new FabricTransportServiceRemotingClientFactory(settings);
                });

        }
    }
    public class CloudFlareZoneServiceWrapper : GatewayManagementServiceClient, ICloudFlareZoneService
    {
        public CloudFlareZoneServiceWrapper(ICodePackageActivationContext codePackageActivationContext) : base(codePackageActivationContext)
        {
        }

        public async Task<string> GetZoneIdAsync(string dnsIdentifier)
        {
            try
            {
                return await GetProxy<ICloudFlareZoneService>(dnsIdentifier).GetZoneIdAsync(dnsIdentifier);
            }catch(Exception ex)
            {
                throw;
            }
        }

        public async Task UpdateZoneIdAsync(string dnsIdentifier, string zoneid)
        {
            try
            {
                await GetProxy<ICloudFlareZoneService>(dnsIdentifier).UpdateZoneIdAsync(dnsIdentifier, zoneid);
            }
            catch (Exception ex)
            {
                throw;
            }
        }
    }
    public class OrdersServicesWrapper : GatewayManagementServiceClient, IOrdersService
    {
        public OrdersServicesWrapper(ICodePackageActivationContext codePackageActivationContext) : base(codePackageActivationContext)
        {
        }

        public async Task ClearOrderAsync(string topLevelDomain)
        {
            try
            {
                await GetProxy<ServiceFabricIOrdersService>(topLevelDomain).ClearOrderAsync(topLevelDomain);
            }catch(Exception ex)
            {
                throw;
            }
        }

        public async Task<string> GetRemoteLocationAsync(string topLevelDomain)
        {
            try
            {
                return await GetProxy<ServiceFabricIOrdersService>(topLevelDomain).GetRemoteLocationAsync(topLevelDomain);
            }catch(Exception ex)
            {
                throw;
            }
        }

        public async Task SetRemoteLocationAsync(string domain, string location)
        {
            try
            {
                await GetProxy<ServiceFabricIOrdersService>(domain).SetRemoteLocationAsync(domain, location);
            }catch(Exception ex)
            {
                throw;
            }
        }
    }
    public class SignersStore : GatewayManagementServiceClient, IRS256SignerStore
    {
        public SignersStore(ICodePackageActivationContext codePackageActivationContext) : base(codePackageActivationContext)
        {
        }

        public async Task<bool> ExistsAsync(string dnsIdentifier)
        {
            try
            {
                return await GetProxy<ServiceFabricIRS256SignerStore>(dnsIdentifier).ExistsAsync(dnsIdentifier);
            }catch(Exception ex)
            {
                throw;
            }
        }

        public async Task<string> GetSignerAsync(string dnsIdentifier)
        {
            try
            {
                return await GetProxy<ServiceFabricIRS256SignerStore>(dnsIdentifier).GetSignerAsync(dnsIdentifier);
            }catch(Exception ex)
            {
                throw;
            }
        }

        public async Task SetSigner(string dnsIdentifier, string cert)
        {
            try
            {
                await GetProxy<ServiceFabricIRS256SignerStore>(dnsIdentifier).SetSigner(dnsIdentifier, cert);
            }catch(Exception ex)
            {
                throw;
            }
        }
    }
    public class CloudFlareDNSClient : IDnsClient
    {



     
        private readonly ICloudFlareZoneService zoneService;


        //private readonly ICloudFlareZoneService zoneService;
        private readonly HttpClient http;
        private readonly string authKey;
        private readonly string authEmail;
        public CloudFlareDNSClient(HttpClient http, IOptions<KeyVaultOptions> secrets, ICloudFlareZoneService zoneService)
        {
            this.zoneService = zoneService ?? throw new ArgumentNullException(nameof(zoneService));

            this.http = http;
           // this.zoneService = cloudFlareZoneService;
            var key = secrets.Value.CloudFlare;

            this.authEmail = key.Substring(0, key.IndexOf(":"));
            this.authKey = key.Substring(key.IndexOf(":") + 1);
        }
        public async Task EnsureTxtRecordCreatedAsync(string dnsIdentifier, string recordName, string recordValue)
        {

          //  var zoneService = ServiceProxy.Create<ICloudFlareZoneService>(new Uri($"{codePackageActivationContext.ApplicationName}/{nameof(GatewayManagementService)}"), dnsIdentifier.ToPartitionHashFunction());

            var zone = await zoneService.GetZoneIdAsync(dnsIdentifier); //  "ac1d153353eebc8508f7bb31ef1ab46c";

            if (!string.IsNullOrEmpty(zone))
            {
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

        public async Task ClearTxtRecordAsync(string dnsIdentifier, string recordName, string recordValue)
        {
            var zone = await zoneService.GetZoneIdAsync(dnsIdentifier);
            if (!string.IsNullOrEmpty(zone))
            {
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




    public static class DsnExtensions
    {
        public static IUnityContainer WithLetsEncryptService(this IUnityContainer container, LetsEncryptServiceOptions options)
        {
            container.RegisterInstance(options);
            container.AddScoped<IRS256SignerStore, SignersStore>();
          //  container.AddScoped<IRS256SignerService, DefaultRS256SignerService>();
            container.AddScoped<IAcmeClientService<AcmeContext>, CertesAcmeClientService>();
            container.AddScoped<IAcmeRegistrationStore, InMemoryAcmeRegistrationStore>();
            
            container.AddScoped<ILetsEncryptChallengeService<AcmeContext>, CertesChallengeService>();
            container.AddScoped<ICloudFlareZoneService, CloudFlareZoneServiceWrapper>();
            container.AddScoped<IOrdersService, OrdersServicesWrapper>();
          
            container.AddScoped<IDnsClient, CloudFlareDNSClient>();

          //  container.AddScoped<DnsMadeEasyClientCredetials, DnsMadeEasyOptions>();
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
