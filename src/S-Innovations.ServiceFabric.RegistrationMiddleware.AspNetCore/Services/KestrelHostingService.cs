using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.ApplicationInsights.ServiceFabric;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Practices.Unity;
using Microsoft.ServiceFabric.Actors;
using Microsoft.ServiceFabric.Actors.Client;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Runtime;
using Serilog;
using Serilog.Extensions.Logging;
using SInnovations.ServiceFabric.Gateway.Actors;
using SInnovations.ServiceFabric.Gateway.Common.Model;
using SInnovations.ServiceFabric.Gateway.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Communication;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Startup;
using SInnovations.ServiceFabric.Unity;
using SInnovations.Unity.AspNetCore;
using System;
using System.Collections.Generic;
using System.Fabric;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Services
{
    public class AzureRegion : ITelemetryProcessor
    {
        public (int,int)[] Ranges { get; set; }

        private ITelemetryProcessor Next { get; set; }

    

        public AzureRegion(ITelemetryProcessor next,string str)
        {
            this.Next = next;

            using (var gzip = new GZipStream(new MemoryStream(Convert.FromBase64String(str)), CompressionMode.Decompress, false))
            {
                Ranges = ((int, int)[])new BinaryFormatter().Deserialize(gzip);
            }
        }
        public bool ContainsIP(string ipAddress)
        {
            int CIDR_addr = BitConverter.ToInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0);


            for (var i = 0; i < Ranges.Length; i++)
            {
               var (IP_addr, CIDR_mask) = Ranges[i];

                if (((IP_addr & CIDR_mask) == (CIDR_addr & CIDR_mask)))
                    return true;
            }

            return false;
          
        }

        private static (int,int) ToIpRange2(string CIDRmask)
        {
            string[] parts = CIDRmask.Split('/');
            int IP_addr = BitConverter.ToInt32(IPAddress.Parse(parts[0]).GetAddressBytes(), 0);
            int CIDR_mask = IPAddress.HostToNetworkOrder(-1 << (32 - int.Parse(parts[1])));

            return (IP_addr, CIDR_mask);
        }

       

        public void Process(ITelemetry item)
        {
            try
            {
                if (ContainsIP(item.Context.Location.Ip))
                {
                    return;
                }
            }catch(Exception ex)
            {

            }
            
            this.Next.Process(item);
        }
    }

    public class KestrelHostingService : StatelessService
    {
        public Action<IWebHostBuilder> WebBuilderConfiguration { get; set; }

        protected KestrelHostingServiceOptions Options { get; set; }
        protected IUnityContainer Container { get; set; }

        private readonly Microsoft.Extensions.Logging.ILogger _logger;
        public KestrelHostingService(
            KestrelHostingServiceOptions options,
            StatelessServiceContext serviceContext,
            ILoggerFactory factory,
            IUnityContainer container)
            : base(serviceContext)
        {
            Options = options;
            Container = container;
            _logger = factory.CreateLogger<KestrelHostingService>();

            _logger.LogInformation("Creating " + nameof(KestrelHostingService) + " for {@options}", Options);
        }

        protected virtual void ConfigureServices(IServiceCollection services)
        {
            _logger.LogInformation("ConfigureServices of {gatewayKey}", Options.GatewayOptions.Key);

            services.AddSingleton(this.Context);
            services.AddSingleton<ServiceContext>(this.Context);
            services.AddSingleton(this);

            services.AddSingleton(Container);
            services.AddSingleton<IServiceProviderFactory<IServiceCollection>>(new UnityServiceProviderFactory(Container));
            services.AddSingleton<IStartupFilter>(new UseForwardedHeadersStartupFilter($"{this.Context.ServiceName.AbsoluteUri.Substring("fabric:/".Length)}/{Context.CodePackageActivationContext.CodePackageVersion}"));

        }


        /// <summary>
        /// Optional override to create listeners (like tcp, http) for this service instance.
        /// </summary>
        /// <returns>The collection of listeners.</returns>
        protected override IEnumerable<ServiceInstanceListener> CreateServiceInstanceListeners()
        {
            return new ServiceInstanceListener[]
            {
                new ServiceInstanceListener(serviceContext =>

                    new CustomKestrelCommunicationListener(serviceContext, Options.ServiceEndpointName, (url,listener) =>
                    {
                        try {

                            _logger.LogInformation("building kestrel app for {url} in {gatewayKey}",url,Options.GatewayOptions.Key);



                            var context =serviceContext.CodePackageActivationContext;
                            var config = context.GetConfigurationPackageObject("Config");

                            var builder=new WebHostBuilder()
                                .UseKestrel()
                                .ConfigureServices(ConfigureServices)
                             //   .UseCustomServiceFabricIntegration(listener as CustomKestrelCommunicationListener , ServiceFabricIntegrationOptions.UseUniqueServiceUrl)
                             //   .ConfigureServices((services)=>{ services.AddTransient<IStartupFilter, UseForwardedHeadersStartupFilter>(); })
                                .UseContentRoot(Directory.GetCurrentDirectory());

                            if (Container.IsRegistered<IConfigureOptions<ApplicationInsights>>())
                            {
                                 builder.UseApplicationInsights(Container.Resolve<ApplicationInsights>().InstrumentationKey);
                            }



                            builder.ConfigureServices((services) =>
                            {
                                services.AddSingleton(listener);
                                services.AddSingleton((sp)=> new KestrelHostingAddresss{Url = this.GetAddresses()["kestrel"]  });
                                services.AddSingleton<ITelemetryInitializer>((serviceProvider) => FabricTelemetryInitializerExtension.CreateFabricTelemetryInitializer(serviceContext));
                                
                            });

                            if (Container.IsRegistered<IConfiguration>())
                            {
                                 _logger.LogInformation("UseConfiguration for {gatewayKey}", Options.GatewayOptions.Key);
                                builder.UseConfiguration(Container.Resolve<IConfiguration>());
                            }


                            if(config.Settings.Sections.Contains("Environment"))
                            {
                                //http://stackoverflow.com/questions/39109666/asp-net-core-environment-variables-not-being-used-when-debugging-through-a-servi

                                

                                var environments =config.Settings.Sections["Environment"];
                                if(environments.Parameters.Contains("ASPNETCORE_ENVIRONMENT"))
                                {
                                    var environment = environments.Parameters["ASPNETCORE_ENVIRONMENT"].Value;
                                    _logger.LogInformation("UseEnvironment {environment} for {gatewayKey}",environment, Options.GatewayOptions.Key);
                                    builder = builder.UseEnvironment(environment);

                                }

                            }

#if NETCORE10
                            if (Container.IsRegistered<ILoggerFactory>())
                            {
                                _logger.LogInformation("UseLoggerFactory for {gatewayKey}", Options.GatewayOptions.Key);
                                builder.UseLoggerFactory(Container.Resolve<ILoggerFactory>());
                            }
#endif

#if NETCORE20

                            if (Container.IsRegistered<LoggerConfiguration>())
                            {
                                Container.RegisterType<SerilogLoggerProvider>(new ContainerControlledLifetimeManager(), new InjectionFactory((c) =>
                                {
                                     var seriologger =new SerilogLoggerProvider(c.Resolve<Serilog.Core.Logger>(),false);
                                    return seriologger;

                                }));
                               
                                builder.ConfigureLogging((hostingContext, logging) =>
                                {                                   
                                    logging.AddProvider(Container.Resolve<SerilogLoggerProvider>());
                                });
                            }
#endif


                            ConfigureBuilder(builder);

                            return builder.UseUrls(url).Build();

                            }catch(Exception ex)
                            {
                                _logger.LogWarning(new EventId(),ex,"failed to build app pipeline");
                                throw;
                            }
                    }),"kestrel")
            };
        }

        public virtual void ConfigureBuilder(IWebHostBuilder builder)
        {
            WebBuilderConfiguration?.Invoke(builder);
        }

        protected override async Task OnOpenAsync(CancellationToken cancellationToken)
        {
            try
            {
                var gateway = ActorProxy.Create<IGatewayServiceManagerActor>(new ActorId(0), "S-Innovations.ServiceFabric.GatewayApplication", "GatewayServiceManagerActorService");


                if (!this.GetAddresses().TryGetValue("kestrel", out string backAddress))
                {

                }

                if (!string.IsNullOrEmpty(Options.ServiceEndpointName))
                {
                    var endpoint = Context.CodePackageActivationContext.GetEndpoint(Options.ServiceEndpointName);
                    backAddress = $"{endpoint.Protocol.ToString().ToLower()}://{Context.NodeContext.IPAddressOrFQDN}:{endpoint.Port}";
                }


                await base.OnOpenAsync(cancellationToken);

                await RegisterGatewayServiceAsync(gateway, backAddress, Options.GatewayOptions);

                foreach (var gw in Options.AdditionalGateways)
                {
                    await RegisterGatewayServiceAsync(gateway, backAddress, gw);
                }


                var builder = TelemetryConfiguration.Active.TelemetryProcessorChainBuilder;
                builder.Use((next) => new AzureRegion(next, "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"));
                builder.Build();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(new EventId(), ex, "OnOpenAsync failed");
                throw;
            }

        }

        private async Task RegisterGatewayServiceAsync(IGatewayServiceManagerActor gateway, string backAddress, GatewayOptions gw)
        {
            await gateway.RegisterGatewayServiceAsync(new GatewayServiceRegistrationData
            {
                Key = $"{gw.Key ?? Context.CodePackageActivationContext.GetServiceManifestName()}-{Context.NodeContext.IPAddressOrFQDN}",
                IPAddressOrFQDN = Context.NodeContext.IPAddressOrFQDN,
                ServerName = gw.ServerName,
                ReverseProxyLocation = gw.ReverseProxyLocation ?? "/",
                Ssl = gw.Ssl,
                BackendPath = backAddress,
                ServiceName = Context.ServiceName,
                ServiceVersion = Context.CodePackageActivationContext.GetServiceManifestVersion(),
                CacheOptions = gw.CacheOptions
            });
        }
    }
    /// <summary>
    /// A specialized stateless service for hosting ASP.NET Core web apps.
    /// </summary>
    public class KestrelHostingService<TStartUp> : KestrelHostingService where TStartUp : class
    {

        public KestrelHostingService(
            KestrelHostingServiceOptions options,
            StatelessServiceContext serviceContext,
            ILoggerFactory factory,
            IUnityContainer container)
            : base(options, serviceContext, factory, container)
        {

        }

        public override void ConfigureBuilder(IWebHostBuilder builder)
        {
            builder.UseStartup<TStartUp>();
        }
    }
}
