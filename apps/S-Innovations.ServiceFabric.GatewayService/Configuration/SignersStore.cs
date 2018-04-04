using System;
using System.Fabric;
using System.Threading.Tasks;
using SInnovations.LetsEncrypt.Stores;
using SInnovations.ServiceFabric.GatewayService.Services;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{
    public class SignersStore : GatewayManagementServiceClient, IRS256SignerStore
    {
        public SignersStore(ICodePackageActivationContext codePackageActivationContext) : base(codePackageActivationContext)
        {
        }

        public async Task<bool> ExistsAsync(string dnsIdentifier)
        {
            try
            {
                return await GetProxy<IServiceFabricIRS256SignerStore>(dnsIdentifier).ExistsAsync(dnsIdentifier);
            }catch(Exception ex)
            {
                throw;
            }
        }

        public async Task<string> GetSignerAsync(string dnsIdentifier)
        {
            try
            {
                return await GetProxy<IServiceFabricIRS256SignerStore>(dnsIdentifier).GetSignerAsync(dnsIdentifier);
            }catch(Exception ex)
            {
                throw;
            }
        }

        public async Task SetSigner(string dnsIdentifier, string cert)
        {
            try
            {
                await GetProxy<IServiceFabricIRS256SignerStore>(dnsIdentifier).SetSigner(dnsIdentifier, cert);
            }catch(Exception ex)
            {
                throw;
            }
        }
    }










}
