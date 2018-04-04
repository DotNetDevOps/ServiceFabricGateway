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
            try
            {
                await GetProxy<IServiceFabricIOrdersService>(topLevelDomain).ClearOrderAsync(topLevelDomain);
            }catch(Exception ex)
            {
                throw;
            }
        }

        public async Task<string> GetRemoteLocationAsync(string topLevelDomain)
        {
            try
            {
                return await GetProxy<IServiceFabricIOrdersService>(topLevelDomain).GetRemoteLocationAsync(topLevelDomain);
            }catch(Exception ex)
            {
                throw;
            }
        }

        public async Task SetRemoteLocationAsync(string domain, string location)
        {
            try
            {
                await GetProxy<IServiceFabricIOrdersService>(domain).SetRemoteLocationAsync(domain, location);
            }catch(Exception ex)
            {
                throw;
            }
        }
    }










}
