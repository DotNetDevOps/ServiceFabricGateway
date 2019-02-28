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
                return await GetProxy<IServiceFabricIRS256SignerStore>(dnsIdentifier).ExistsAsync(dnsIdentifier);
             
        }

        public async Task<string> GetSignerAsync(string dnsIdentifier)
        {
            
                return await GetProxy<IServiceFabricIRS256SignerStore>(dnsIdentifier).GetSignerAsync(dnsIdentifier);
            
        }

        public async Task SetSigner(string dnsIdentifier, string cert)
        {  
                await GetProxy<IServiceFabricIRS256SignerStore>(dnsIdentifier).SetSigner(dnsIdentifier, cert);
             
        }
    }










}
