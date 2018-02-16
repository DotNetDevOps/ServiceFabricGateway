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
            container.AddScoped<IDnsClient, LetsEncryptDnsMadeEasyManager>();
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
    }

    
  
    



    

   
}
