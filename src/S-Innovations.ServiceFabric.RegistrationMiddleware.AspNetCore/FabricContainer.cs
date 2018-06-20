using Unity;
using SInnovations.ServiceFabric.Unity;
using SInnovations.Unity.AspNetCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting.Internal;
using Microsoft.Extensions.Configuration;
using System.Reflection;
using System;
using System.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Unity.Lifetime;
//#if NETCORE20
using Unity.Microsoft.DependencyInjection;

//#endif

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore
{


    public class FabricContainer : UnityContainer, IServiceScopeInitializer
    {

        private static string ResolveContentRootPath(string contentRootPath, string basePath)
        {
            if (string.IsNullOrEmpty(contentRootPath))
            {
                return basePath;
            }
            if (Path.IsPathRooted(contentRootPath))
            {
                return contentRootPath;
            }
            return Path.Combine(Path.GetFullPath(basePath), contentRootPath);
        }

        public FabricContainer(ServiceCollection services =null)
        {
            services = services ?? new ServiceCollection();

            this.RegisterInstance<IServiceScopeInitializer>(this);

//#if NETCORE20

            this.AsFabricContainer().BuildServiceProvider(services) ;
//#else
//            this.AsFabricContainer().WithAspNetCoreServiceProvider();
//#endif

            var _hostingEnvironment = new HostingEnvironment();
            var _config = new ConfigurationBuilder()
                .AddEnvironmentVariables(prefix: "ASPNETCORE_")
                .Build();
            var _options = new WebHostOptions(_config, Assembly.GetEntryAssembly()?.GetName().Name)
            {
                
            };
           // Microsoft.AspNetCore.Hosting.Internal.HostingEnvironmentExtensions.Initialize

            var contentRootPath = ResolveContentRootPath(_options.ContentRootPath, AppContext.BaseDirectory); 
            _hostingEnvironment.Initialize(contentRootPath, _options);
            this.RegisterInstance<IHostingEnvironment>(_hostingEnvironment);
        }
        public IUnityContainer InitializeScope(IUnityContainer container)
        {
//#if NETCORE20

            var child = container.CreateChildContainer()
                .RegisterType<ILoggerFactory, LoggerFactory>(new ContainerControlledLifetimeManager());

            child.BuildServiceProvider(new ServiceCollection());
            return child;

          //  var child= fac.CreateBuilder();

         //   fac.CreateServiceProvider(child);

        //    return child;
//#else
//            return container.WithAspNetCoreServiceProvider();
//#endif
        }

       
    }
}
