using Autofac;
using DotNetDevOps.ServiceFabric.Hosting;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.Client;
using Serilog;
using SInnovations.ServiceFabric.Gateway.Common.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Services;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Extensions
{

    public static class KestrelHostingExtensions
    {
        private static List<Action<IComponentContext,LoggerConfiguration>> _configurations = new List<Action<IComponentContext,LoggerConfiguration>>();
        public static IHostBuilder ConfigureSerilogging(this IHostBuilder container, Action<IComponentContext,LoggerConfiguration> configure)
        {
            container.ConfigureContainer< ContainerBuilder>((context, builder) =>
            {

                builder.RegisterType<LoggerConfiguration>().AsSelf().SingleInstance().IfNotRegistered(typeof(LoggerConfiguration));

                builder.Register(c=>
                {
                    var configuration = c.Resolve<LoggerConfiguration>();

                    foreach (var modify in _configurations)
                    {
                        modify(c,configuration);
                    }

                    return configuration.CreateLogger();
                }).AsSelf().SingleInstance().IfNotRegistered(typeof(Serilog.Core.Logger));

                builder.Register(c =>
                       {
                           var filters = new LoggerFilterOptions()
                               .AddFilter("System", LogLevel.Warning)
                               .AddFilter("Microsoft", LogLevel.Warning)
                               .AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Information);

                           var factory = new LoggerFactory(Enumerable.Empty<ILoggerProvider>(), filters);



                           factory.AddSerilog(c.Resolve<Serilog.Core.Logger>());
                           return factory;

                       }).AsSelf().As<ILoggerFactory>().SingleInstance().IfNotRegistered(typeof(LoggerConfiguration));
            });

            _configurations.Add(configure);

            //configure(container.Resolve<LoggerConfiguration>());

            return container;
        }

        
        public static IHostBuilder ConfigureApplicationInsights(this IHostBuilder container)
        {


            container.Configure<ApplicationInsights>("ApplicationInsights");

            container.ConfigureSerilogging((context,logConfiguration) =>
            {

                logConfiguration.WriteTo.ApplicationInsightsTraces(context.Resolve<IOptions<ApplicationInsights>>().Value.InstrumentationKey, Serilog.Events.LogEventLevel.Information);

               
            });
          

            return container;
        }

        public static IHostBuilder WithServiceProxy<TServiceInterface>(this IHostBuilder container, string serviceName, string listenerName = null)
            where TServiceInterface : class,IService
        {
            container.ConfigureServices(services =>
            {
                services.AddScoped(c=> ServiceProxy.Create<TServiceInterface>(
                          new Uri(serviceName), listenerName: listenerName));
            });
            //return container.RegisterType<TServiceInterface>(new HierarchicalLifetimeManager(),
            //          new InjectionFactory(c => ServiceProxy.Create<TServiceInterface>(
            //              new Uri(serviceName), listenerName: listenerName)));

            return container;

        }
        public static IHostBuilder WithKestrelHosting<TStartup>(this IHostBuilder container, string serviceType, KestrelHostingServiceOptions options)
            where TStartup : class
        {
            return container.WithKestrelHosting<KestrelHostingService<TStartup>, TStartup>(serviceType, options);
        }
        public static IHostBuilder WithKestrelHosting<TStartup>(this IHostBuilder container, string serviceType, Func<IComponentContext, KestrelHostingServiceOptions> options)
         where TStartup : class
        {
            return container.WithKestrelHosting<KestrelHostingService<TStartup>, TStartup>(serviceType, options);
        }

        public static IHostBuilder WithKestrelHosting<THostingService, TStartup>(this IHostBuilder container, string serviceType, KestrelHostingServiceOptions options)
          where THostingService : KestrelHostingService<TStartup>
          where TStartup : class
        {

            container.WithStatelessService<THostingService>(serviceType, child => { child.RegisterInstance(options); });
            return container;
        }
        public static IHostBuilder WithKestrelHosting<THostingService, TStartup>(this IHostBuilder container, string serviceType, Func<IComponentContext, KestrelHostingServiceOptions> options)
          where THostingService : KestrelHostingService<TStartup>
          where TStartup : class
        {
            
            container.WithStatelessService<THostingService>(serviceType, child => { child.Register(options).AsSelf().SingleInstance(); });
            return container;
        }


        public static IHostBuilder WithKestrelHosting(this IHostBuilder container, string serviceType, KestrelHostingServiceOptions options, Action<IWebHostBuilder> builder)
        {
            container.WithStatelessService<KestrelHostingService>(serviceType, child =>
            {
                child.RegisterInstance(options);
                child.RegisterType<KestrelHostingService>().WithProperty("WebBuilderConfiguration", builder);
             //   child.RegisterType<KestrelHostingService>(new InjectionProperty("WebBuilderConfiguration", builder));
            });

            return container;
        }

        public static string BuildResourceProviderLocation(this IEnumerable<string> providers, bool subscriptions = true, bool resourceGroup = true)
        {
            return $"~* ^/{(subscriptions ? "(subscriptions/[^/]+/)?" : "")}{(resourceGroup ? "(resourcegroups/[^/]+/)?" : "")}providers/({string.Join("|", providers)})";
        }
    }
}
