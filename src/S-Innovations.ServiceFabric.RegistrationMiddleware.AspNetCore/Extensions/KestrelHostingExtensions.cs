using Autofac;
using DotNetDevOps.ServiceFabric.Hosting;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.ApplicationInsights.ServiceFabric;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.Client;
using Serilog;
using Serilog.Sinks.ApplicationInsights.Sinks.ApplicationInsights.TelemetryConverters;
using SInnovations.ServiceFabric.Gateway.Common.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Extensions
{

    public static class KestrelHostingExtensions
    {
        private static List<Action<HostBuilderContext, LoggerConfiguration>> _configurations = new List<Action<HostBuilderContext, LoggerConfiguration>>();
       
        public static IHostBuilder ConfigureSerilogging(this IHostBuilder container, Action<HostBuilderContext, LoggerConfiguration> configure)
        {

            //container.ConfigureServices((context, services) =>
            //{
            //    if (!context.Properties.ContainsKey("ConfigureSerilogging"))
            //    {
            //        services.AddSingleton<LoggerConfiguration>();
            //        services.AddSingleton((sp) =>
            //        {
            //            var configuration = sp.GetService<LoggerConfiguration>();

            //            foreach (var modify in _configurations)
            //            {
            //                try
            //                {
            //                    var scope = sp.GetService<ILifetimeScope>();
            //                    modify(scope, configuration);
            //                }
            //                catch (Exception ex)
            //                {

            //                }
            //            }

            //            return configuration.CreateLogger();
            //        });

            //        services.AddSingleton(c =>
            //        {
            //            var filters = new LoggerFilterOptions()
            //                .AddFilter("System", LogLevel.Warning)
            //                .AddFilter("Microsoft", LogLevel.Warning)
            //                .AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Information);

            //            var factory = new LoggerFactory(Enumerable.Empty<ILoggerProvider>(), filters);

            //            var logger = c.GetService<Serilog.Core.Logger>();

            //            factory.AddSerilog(logger);
            //            return factory;

            //        });

            //        services.AddSingleton<ILoggerFactory>(sp => sp.GetService<LoggerFactory>());
            //        context.Properties["ConfigureSerilogging"] = "true";
            //    }
            //});
            //container.ConfigureServices((context, services) =>
            //{
            //    services.AddSingleton<ILoggerFactory>(sp => sp.GetService<ILifetimeScope>().Resolve<LoggerFactory>());
            //});

            container.ConfigureContainer<ContainerBuilder>((context, builder) =>
           {
               if (!context.Properties.ContainsKey("ConfigureSerilogging"))
               {

                   builder.RegisterType<LoggerConfiguration>().AsSelf().SingleInstance();

                   builder.Register(c =>
                   {
                       var configuration = c.Resolve<LoggerConfiguration>();

                       foreach (var modify in _configurations)
                       {
                           modify(context, configuration);
                       }

                       return configuration.CreateLogger();
                   }).AsSelf().SingleInstance();

                   builder.Register(c =>
                          {
                              var filters = new LoggerFilterOptions()
                                  .AddFilter("System", LogLevel.Warning)
                                  .AddFilter("Microsoft", LogLevel.Warning)
                                  .AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Information);

                              var factory = new LoggerFactory(Enumerable.Empty<ILoggerProvider>(), filters);



                              factory.AddSerilog(c.Resolve<Serilog.Core.Logger>());
                              return factory;

                          }).AsSelf().As<ILoggerFactory>().SingleInstance();
                   context.Properties["ConfigureSerilogging"] = "true";
               }
           });

            _configurations.Add(configure);

            //configure(container.Resolve<LoggerConfiguration>());

            return container;
        }


        public static IHostBuilder ConfigureApplicationInsights(this IHostBuilder container)
        {


            container.Configure<ApplicationInsights>("ApplicationInsights");

            container.ConfigureSerilogging((context, logConfiguration) =>
            {

                //  var opt = context.Resolve<IOptions<ApplicationInsights>>();
                var appInsights = new ApplicationInsights();
                context.Configuration.GetSection("ApplicationInsights").Bind(appInsights);
               
                logConfiguration.WriteTo.ApplicationInsights(appInsights.InstrumentationKey,TelemetryConverter.Traces);


            });
            container.ConfigureContainer<ContainerBuilder>(services =>
            {
                services.RegisterInstance(new OptionRegistration {
                    ServiceType = typeof(Microsoft.AspNetCore.Hosting.IHostingEnvironment), ServiceLifetime = ServiceLifetime.Singleton, ShouldIgnore=true });

            });
            container.ConfigureServices((context,services) =>
            {
                var _hostingEnvironment = new Microsoft.AspNetCore.Hosting.Internal.HostingEnvironment();


                var _options = new WebHostOptions(context.Configuration, Assembly.GetEntryAssembly()?.GetName().Name)
                {

                };
                // Microsoft.AspNetCore.Hosting.Internal.HostingEnvironmentExtensions.Initialize

                var contentRootPath = ResolveContentRootPath(_options.ContentRootPath, AppContext.BaseDirectory);
                _hostingEnvironment.Initialize(contentRootPath, _options);

                services.AddSingleton<Microsoft.AspNetCore.Hosting.IHostingEnvironment>(_hostingEnvironment);
              

                services.AddApplicationInsightsTelemetry();

                services
                                      // .AddSingleton<ITelemetryInitializer>((serviceProvider) => FabricTelemetryInitializerExtension.CreateFabricTelemetryInitializer(serviceContext))
                                       .AddSingleton<ITelemetryModule>(new MyServiceRemotingDependencyTrackingTelemetryModule())
                                       .AddSingleton<ITelemetryModule>(new MyServiceRemotingRequestTrackingTelemetryModule())
                                       .AddSingleton<ITelemetryInitializer>(new CodePackageVersionTelemetryInitializer())
                                       .AddSingleton<ITelemetryModule>(new MyTestModule());

            });

            return container;
        }
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

        public static IHostBuilder WithServiceProxy<TServiceInterface>(this IHostBuilder container, string serviceName, string listenerName = null)
            where TServiceInterface : class, IService
        {
            container.ConfigureServices(services =>
            {
                services.AddScoped(c => ServiceProxy.Create<TServiceInterface>(
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

            container.WithStatelessService<THostingService>(serviceType, (child,context) => { child.RegisterInstance(options); });
            return container;
        }
        public static IHostBuilder WithKestrelHosting<THostingService, TStartup>(this IHostBuilder container, string serviceType, Func<IComponentContext, KestrelHostingServiceOptions> options)
          where THostingService : KestrelHostingService<TStartup>
          where TStartup : class
        {

            container.WithStatelessService<THostingService>(serviceType, (child,contex) => { child.Register(options).AsSelf().SingleInstance(); });
            return container;
        }


        public static IHostBuilder WithKestrelHosting(this IHostBuilder container, string serviceType, KestrelHostingServiceOptions options, Action<IWebHostBuilder> builder)
        {
            container.WithStatelessService<KestrelHostingService>(serviceType, (child,context) =>
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
