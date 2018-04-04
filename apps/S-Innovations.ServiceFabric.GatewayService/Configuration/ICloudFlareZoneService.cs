using System.Threading.Tasks;
using Microsoft.ServiceFabric.Services.Remoting;

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










}
