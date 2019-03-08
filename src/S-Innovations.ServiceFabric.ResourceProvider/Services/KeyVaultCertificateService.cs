using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.Options;
using SInnovations.ServiceFabric.Gateway.Common.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.ResourceProvider.Services
{
    public class KeyVaultCertificateServiceOptions{
        public string KeyVaultUri { get; set; }
        public string CertificateSecretName { get; set; } = "idsrv";
    }
    public class KeyVaultCertificateService
    {
        private readonly KeyVaultCertificateServiceOptions _keyVaultCertificateServiceOptions;
        private readonly IAzureADTokenService azureAD;

        public KeyVaultClient Client { get; set; }

        public KeyVaultCertificateService(IOptions<KeyVaultCertificateServiceOptions> keyVaultCertificateServiceOptions, IAzureADTokenService azureAD)
        {
            this._keyVaultCertificateServiceOptions = keyVaultCertificateServiceOptions?.Value ?? throw new ArgumentNullException(nameof(keyVaultCertificateServiceOptions));
            this.azureAD = azureAD ?? throw new ArgumentNullException(nameof(azureAD));

            KeyVaultClient.AuthenticationCallback callback =
              (authority, resource, scope) => this.azureAD.GetTokenForResourceAsync(resource);

            Client = new KeyVaultClient(callback);

        }

        public async Task<X509Certificate2[]> GetCerts()
        {
            
            var certsVersions = await Client.GetSecretVersionsAsync(_keyVaultCertificateServiceOptions.KeyVaultUri, _keyVaultCertificateServiceOptions.CertificateSecretName);

            var secrets = await Task.WhenAll(certsVersions.Select(k => Client.GetSecretAsync(k.Identifier.Identifier)));

            var certs = secrets.Select(s => new X509Certificate2(Convert.FromBase64String(s.Value), (string)null, X509KeyStorageFlags.MachineKeySet)).ToArray();
            return certs;

        }
    }
}
