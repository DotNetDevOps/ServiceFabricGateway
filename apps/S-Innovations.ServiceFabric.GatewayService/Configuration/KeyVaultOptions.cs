using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Configuration.AzureKeyVault;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Newtonsoft.Json;
using SInnovations.LetsEncrypt.DnsMadeEasyManager;
using SInnovations.ServiceFabric.Storage.Configuration;
using Unity.Lifetime;
using SInnovations.ServiceFabric.GatewayService.Actors;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{

    public class KeyVaultOptions
    {
        public string DnsMadeEasyCredentials { get; set; }
        public string CloudFlare { get; set; }
    }










}
