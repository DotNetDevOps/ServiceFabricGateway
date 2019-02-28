using System;
using System.Fabric;
using System.Threading.Tasks;
using SInnovations.LetsEncrypt.Services.Defaults;
using SInnovations.ServiceFabric.GatewayService.Services;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{
    public class OrdersServicesWrapper : GatewayManagementServiceClient, IOrdersService
    {
        public OrdersServicesWrapper(ICodePackageActivationContext codePackageActivationContext) : base(codePackageActivationContext)
        {
        }

        public async Task ClearOrderAsync(string topLevelDomain)
        {
             
                await GetProxy<IServiceFabricIOrdersService>(topLevelDomain).ClearOrderAsync(topLevelDomain);
             
        }

        public async Task<string> GetRemoteLocationAsync(string topLevelDomain)
        {
            
                return await GetProxy<IServiceFabricIOrdersService>(topLevelDomain).GetRemoteLocationAsync(topLevelDomain);
            
        }

        public async Task SetRemoteLocationAsync(string domain, string location)
        {
            
                await GetProxy<IServiceFabricIOrdersService>(domain).SetRemoteLocationAsync(domain, location);
           
        }
    }










}
