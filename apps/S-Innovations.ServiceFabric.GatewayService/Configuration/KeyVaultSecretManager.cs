using DotNetDevOps.ServiceFabric.Hosting;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.AzureKeyVault;
using Microsoft.Extensions.Logging;
using SInnovations.ServiceFabric.Storage.Configuration;
using System.Fabric;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{
    public class KeyVaultSecretManager : IKeyVaultSecretManager , IConfigurationBuilderExtension
    {
        private readonly ILogger Logger;
        private readonly AzureADConfiguration AzureAD;
        public string KeyVaultUrl { get; set; }
        public KeyVaultClient Client { get; set; }

        public KeyVaultSecretManager(
          ConfigurationPackage configurationPackage,
          AzureADConfiguration AzureAd,
          ILoggerFactory logFactory)
        {
            this.Logger = logFactory.CreateLogger<StorageConfiguration>();
            this.AzureAD = AzureAd;

            var section = configurationPackage.Settings.Sections["AzureResourceManager"].Parameters;
            KeyVaultUrl = section["Azure.KeyVault.Uri"].Value;

            KeyVaultClient.AuthenticationCallback callback =
                (authority, resource, scope) => AzureAD.GetTokenFromClientSecret(authority, resource);

            Client = new KeyVaultClient(callback);
        }


        /// <inheritdoc />
        public virtual string GetKey(SecretBundle secret)
        {

            return "KeyVault:" + secret.SecretIdentifier.Name.Replace("--", ConfigurationPath.KeyDelimiter);
        }

        /// <inheritdoc />
        public virtual bool Load(SecretItem secret)
        {

            return true;
        }

        public IConfigurationBuilder Extend(IConfigurationBuilder cbuilder)
        {
           return cbuilder.AddAzureKeyVault(KeyVaultUrl, Client, this);
        }
    }
}
