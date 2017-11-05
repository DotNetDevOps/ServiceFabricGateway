using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Unity;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.Client;
using Serilog;
using SInnovations.ServiceFabric.Gateway.Common.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Services;
using SInnovations.ServiceFabric.Unity;
using SInnovations.Unity.AspNetCore;
using System;
using Unity.Injection;
using Unity.Lifetime;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Extensions
{
    public static class KestrelHostingExtensions
    {
        public static IUnityContainer ConfigureSerilogging(this IUnityContainer container, Action<LoggerConfiguration> configure)
        {
            if (!container.IsRegistered<LoggerConfiguration>())
            {
                container.RegisterType<Serilog.Core.Logger>(new ContainerControlledLifetimeManager(),
                    new InjectionFactory(c => c.Resolve<LoggerConfiguration>().CreateLogger()));

                container.RegisterInstance(new LoggerConfiguration());
                container.RegisterType<ILoggerFactory>(new ContainerControlledLifetimeManager(),
                     new InjectionFactory((c) => new LoggerFactory().AddSerilog(c.Resolve<Serilog.Core.Logger>())));
            }

            configure(container.Resolve<LoggerConfiguration>());

            return container;
        }
        public static IUnityContainer ConfigureApplicationInsights(this IUnityContainer container)
        {


            container.Configure<ApplicationInsights>("ApplicationInsights");

            container.ConfigureSerilogging((logConfiguration) =>
            {

                logConfiguration.WriteTo.ApplicationInsightsTraces(container.Resolve<ApplicationInsights>().InstrumentationKey, Serilog.Events.LogEventLevel.Information);

               
            });
          

            return container;
        }

        public static IUnityContainer WithServiceProxy<TServiceInterface>(this IUnityContainer container, string serviceName, string listenerName = null)
            where TServiceInterface : IService
        {
            return container.RegisterType<TServiceInterface>(new HierarchicalLifetimeManager(),
                      new InjectionFactory(c => ServiceProxy.Create<TServiceInterface>(
                          new Uri(serviceName), listenerName: listenerName)));

        }
        public static IUnityContainer WithKestrelHosting<TStartup>(this IUnityContainer container, string serviceType, KestrelHostingServiceOptions options)
            where TStartup : class
        {
            return container.WithKestrelHosting<KestrelHostingService<TStartup>, TStartup>(serviceType, options);
        }

        public static IUnityContainer WithKestrelHosting<THostingService, TStartup>(this IUnityContainer container, string serviceType, KestrelHostingServiceOptions options)
          where THostingService : KestrelHostingService<TStartup>
          where TStartup : class
        {

            container.WithStatelessService<THostingService>(serviceType, child => { child.RegisterInstance(options); });
            return container;
        }

        public static IUnityContainer WithKestrelHosting(this IUnityContainer container, string serviceType, KestrelHostingServiceOptions options, Action<IWebHostBuilder> builder)
        {
            container.WithStatelessService<KestrelHostingService>(serviceType, child =>
            {
                child.RegisterInstance(options);
                child.RegisterType<KestrelHostingService>(new InjectionProperty("WebBuilderConfiguration", builder));
            });

            return container;
        }
    }
}
