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
using Microsoft.Extensions.Options;
using System.Collections.Generic;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Extensions
{
    public static class KestrelHostingExtensions
    {
        private static List<Action<LoggerConfiguration>> _configurations = new List<Action<LoggerConfiguration>>();
        public static IUnityContainer ConfigureSerilogging(this IUnityContainer container, Action<LoggerConfiguration> configure)
        {
            if (!container.IsRegistered<LoggerConfiguration>())
            {
                container.RegisterType<Serilog.Core.Logger>(new ContainerControlledLifetimeManager(),
                    new InjectionFactory(c => {
                        var configuration = c.Resolve<LoggerConfiguration>();

                        foreach (var modify in _configurations)
                        {
                            modify(configuration);
                        }

                        return configuration.CreateLogger();


                        }));

                container.RegisterInstance(new LoggerConfiguration());
                container.RegisterType<ILoggerFactory>(new ContainerControlledLifetimeManager(),
                     new InjectionFactory((c) => {

                        

                         return new LoggerFactory().AddSerilog(c.Resolve<Serilog.Core.Logger>());

                         }));
            }

            _configurations.Add(configure);

            //configure(container.Resolve<LoggerConfiguration>());

            return container;
        }
        public static IUnityContainer ConfigureApplicationInsights(this IUnityContainer container)
        {


            container.Configure<ApplicationInsights>("ApplicationInsights");

            container.ConfigureSerilogging((logConfiguration) =>
            {

                logConfiguration.WriteTo.ApplicationInsightsTraces(container.Resolve<IOptions<ApplicationInsights>>().Value.InstrumentationKey, Serilog.Events.LogEventLevel.Information);

               
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

        public static string BuildResourceProviderLocation(this IEnumerable<string> providers, bool subscriptions = true, bool resourceGroup = true)
        {
            return $"~* ^/{(subscriptions ? "(subscriptions/.*/)?" : "")}{(resourceGroup ? "(resourcegroups/.*/)?" : "")}providers/({string.Join(" | ", providers)})";
        }
    }
}
