using Microsoft.Extensions.Configuration;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Configuration
{
    public class ServiceFabricConfigSource : IConfigurationSource
    {
        public string PackageName { get; set; }

        public ServiceFabricConfigSource(string packageName)
        {
            PackageName = packageName;
        }

        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            return new ServiceFabricConfigurationProvider(PackageName);
        }
    }
}
