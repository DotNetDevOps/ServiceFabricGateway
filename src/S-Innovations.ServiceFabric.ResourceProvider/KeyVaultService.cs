using Microsoft.Extensions.Configuration;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.ServiceFabric.Services.Remoting.Runtime;
using Microsoft.ServiceFabric.Services.Runtime;
using System.Fabric;

 

namespace SInnovations.ServiceFabric.ResourceProvider
{
    public class KeyVaultService : StatelessService, IKeyVaultService
    {
        private readonly IConfigurationRoot configuration;

        public KeyVaultService(StatelessServiceContext serviceContext, IConfigurationRoot configuration) : base(serviceContext)
        {
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }



        protected override IEnumerable<ServiceInstanceListener> CreateServiceInstanceListeners()
        {
            return this.CreateServiceRemotingInstanceListeners();
        }


        public Task<string> GetSecretAsync(string key)
        {
            return Task.FromResult(configuration.GetSection("KeyVault")[key]);
        }
    }

}
