using System;
using System.Fabric;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{
    public class CloudFlareZoneServiceWrapper : GatewayManagementServiceClient, ICloudFlareZoneService
    {
        public CloudFlareZoneServiceWrapper(ICodePackageActivationContext codePackageActivationContext) : base(codePackageActivationContext)
        {
        }

        public async Task<string> GetZoneIdAsync(string dnsIdentifier)
        {
            
                return await GetProxy<ICloudFlareZoneService>(dnsIdentifier).GetZoneIdAsync(dnsIdentifier);
            
        }

        public async Task UpdateZoneIdAsync(string dnsIdentifier, string zoneid)
        {
            
                await GetProxy<ICloudFlareZoneService>(dnsIdentifier).UpdateZoneIdAsync(dnsIdentifier, zoneid);
           
        }
    }










}
