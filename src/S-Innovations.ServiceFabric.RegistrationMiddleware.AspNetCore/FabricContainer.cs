using Unity;
using SInnovations.ServiceFabric.Unity;
using SInnovations.Unity.AspNetCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
#if NETCORE20
using Unity.Microsoft.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
#endif

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore
{
    public class FabricContainer : UnityContainer, IServiceScopeInitializer
    {

#if NETCORE20
        private readonly ServiceProviderFactory fac;

#endif

        public FabricContainer()
        {
            
            this.RegisterInstance<IServiceScopeInitializer>(this);

#if NETCORE20
            fac = new ServiceProviderFactory(this);
            this.AsFabricContainer();
#else
            this.AsFabricContainer().WithAspNetCoreServiceProvider();
#endif

            this.AddNewExtension<EnumerableExtension>();
        }
        public IUnityContainer InitializeScope(IUnityContainer container)
        {
#if NETCORE20


            var child= fac.CreateBuilder(new ServiceCollection());

            fac.CreateServiceProvider(child);

            return child;
#else
            return container.WithAspNetCoreServiceProvider();
#endif
        }
    }
}
