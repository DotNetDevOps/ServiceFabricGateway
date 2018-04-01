using Unity;
using SInnovations.ServiceFabric.Unity;
using SInnovations.Unity.AspNetCore;
using Microsoft.Extensions.DependencyInjection;
#if NETCORE20
using Unity.Microsoft.DependencyInjection;

#endif

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore
{


    public class FabricContainer : UnityContainer, IServiceScopeInitializer
    {

 

        public FabricContainer(ServiceCollection services =null)
        {
            services = services ?? new ServiceCollection();

            this.RegisterInstance<IServiceScopeInitializer>(this);

#if NETCORE20

            this.AsFabricContainer().BuildServiceProvider(services) ;
#else
            this.AsFabricContainer().WithAspNetCoreServiceProvider();
#endif

          
        }
        public IUnityContainer InitializeScope(IUnityContainer container)
        {
#if NETCORE20

            var child = container.CreateChildContainer();
            new ServiceCollection().BuildServiceProvider(child);
            return child;

          //  var child= fac.CreateBuilder();

         //   fac.CreateServiceProvider(child);

        //    return child;
#else
            return container.WithAspNetCoreServiceProvider();
#endif
        }
    }
}
