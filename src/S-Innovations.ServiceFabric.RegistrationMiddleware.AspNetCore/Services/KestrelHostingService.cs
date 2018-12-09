using Autofac;
using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.ApplicationInsights.Extensibility.Implementation;
using Microsoft.ApplicationInsights.ServiceFabric;
using Microsoft.ApplicationInsights.ServiceFabric.Module;
using Microsoft.ApplicationInsights.WindowsServer.TelemetryChannel;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Remoting.Client;
using Microsoft.ServiceFabric.Services.Runtime;
using Serilog;
using Serilog.Extensions.Logging;
using SInnovations.ServiceFabric.Gateway.Actors;
using SInnovations.ServiceFabric.Gateway.Common.Extensions;
using SInnovations.ServiceFabric.Gateway.Common.Model;
using SInnovations.ServiceFabric.Gateway.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Communication;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Startup;
using System;
using System.Collections.Generic;
using System.Fabric;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Autofac.Extensions.DependencyInjection;
using Autofac.Core;
using Autofac.Core.Lifetime;
using Microsoft.AspNetCore.Builder;
using DotNetDevOps.ServiceFabric.Hosting;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Services
{
    //public class AzureRegion : ITelemetryProcessor
    //{
    //    public int[] Ranges { get; set; }

    //    private ITelemetryProcessor Next { get; set; }



    //    public AzureRegion(ITelemetryProcessor next,string str)
    //    {
    //        this.Next = next;

    //        try
    //        {
    //            using (var gzip = new GZipStream(new MemoryStream(Convert.FromBase64String(str)), CompressionMode.Decompress, false))
    //            {
    //                Ranges = (int[])new BinaryFormatter().Deserialize(gzip);
    //            }
    //        }
    //        catch(Exception ex)
    //        {

    //        }
    //    }
    //    public bool ContainsIP(string ipAddress)
    //    {
    //        int CIDR_addr = BitConverter.ToInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0);


    //        for (var i = 0; i < Ranges.Length; i += 2)
    //        {
    //            var IP_addr = Ranges[i];
    //            var CIDR_mask = Ranges[i + 1];


    //            if (((IP_addr & CIDR_mask) == (CIDR_addr & CIDR_mask)))
    //                return true;
    //        }

    //        return false;

    //    }

    //    //private static (int,int) ToIpRange2(string CIDRmask)
    //    //{
    //    //    string[] parts = CIDRmask.Split('/');
    //    //    int IP_addr = BitConverter.ToInt32(IPAddress.Parse(parts[0]).GetAddressBytes(), 0);
    //    //    int CIDR_mask = IPAddress.HostToNetworkOrder(-1 << (32 - int.Parse(parts[1])));

    //    //    return (IP_addr, CIDR_mask);
    //    //}



    //    public void Process(ITelemetry item)
    //    {
    //        try
    //        {
    //            if (ContainsIP(item.Context.Location.Ip))
    //            {
    //                item.Context.Properties["IP_IS_AZURE"] = "true";
    //            }
    //        }catch(Exception ex)
    //        {

    //        }

    //        this.Next.Process(item);
    //    }
    //}

    public class MyServiceRemotingDependencyTrackingTelemetryModule : ServiceRemotingDependencyTrackingTelemetryModule
    {

        protected override void Dispose(bool disposing)
        {
            try
            {
                base.Dispose(disposing);
            }catch(Exception ex)
            {

            }
        }
    }
    public class MyServiceRemotingRequestTrackingTelemetryModule : ServiceRemotingRequestTrackingTelemetryModule
    {
        public MyServiceRemotingRequestTrackingTelemetryModule()
        {

        }
        protected override void Dispose(bool disposing)
        {
            try
            {
                base.Dispose(disposing);
            }
            catch (Exception ex)
            {

            }
        }
    }
    public class ContainerBuilderWrap
    {
        public ILifetimeScope Parent { get; internal set; }
        public IServiceCollection Services { get; internal set; }
    }
     
    public class Test : IServiceProviderFactory<ContainerBuilder>
    {
        private readonly ILifetimeScope container;

        public Test(ILifetimeScope parent)
        {
            this.container = parent ?? throw new ArgumentNullException(nameof(parent));
        }

        //public ContainerBuilderWrap CreateBuilder(IServiceCollection services)
        //{
        //    return new ContainerBuilderWrap
        //    {
        //        Parent = parent,
        //        Services = services,
        //    };



          
        //}
        public ContainerBuilder CreateBuilder(IServiceCollection services)
        {
            var builder = new ContainerBuilder();



            //var components = container.ComponentRegistry.Registrations
            //        .Where(cr => cr.Activator.LimitType != typeof(LifetimeScope));
                    
            //      //  .Where(cr => cr.Activator.LimitType != typeof(MyType));
            //foreach (var c in components)
            //{
            //    builder.RegisterComponent(c);
            //}

            //foreach (var source in container.ComponentRegistry.Sources)
            //{
            //    builder.RegisterSource(source);
            //}

            builder.Populate(services);

            //   _configurationAction(builder);

            return builder;
        }
        public IServiceProvider CreateServiceProvider(ContainerBuilder containerBuilder)
        {
            if (containerBuilder == null) throw new ArgumentNullException(nameof(containerBuilder));

            var container = containerBuilder.Build();

            return new AutofacServiceProvider(container);
        }
        //public IServiceProvider CreateServiceProvider(ContainerBuilderWrap containerBuilder)
        //{
        //    var scope = containerBuilder.Parent.BeginLifetimeScope(containerBuilder.Parent.Tag + $"[{new Random().Next(100)}]", builder =>
        //    {
        //        builder.Populate(containerBuilder.Services);
        //      // builder.()
        //       // builder.
        //    });
         
        //    var serviceProvider = new AutofacServiceProvider(scope);
        //    return serviceProvider;
        //}
    }
    internal class ApplicationInsightsStartupFilter1 : IStartupFilter
    {
        /// <inheritdoc/>
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                // Attemping to resolve TelemetryConfiguration triggers configuration of the same
                // via <see cref="TelemetryConfigurationOptionsSetup"/> class which triggers
                // initialization of TelemetryModules and construction of TelemetryProcessor pipeline.
                var tc = app.ApplicationServices.GetService<IOptions<TelemetryConfiguration>>();
                //var applicationInsightsDebugLogger = app.ApplicationServices.GetService<ApplicationInsightsDebugLogger>();
                next(app);
            };
        }
    }

    public class KestrelHostingService : StatelessService, IApplicationManager
    {
        public Action<IWebHostBuilder> WebBuilderConfiguration { get; set; }

        protected KestrelHostingServiceOptions Options { get; set; }
        protected ILifetimeScope Container { get; set; }

        private readonly Microsoft.Extensions.Logging.ILogger _logger;
        public KestrelHostingService(
            KestrelHostingServiceOptions options,
            StatelessServiceContext serviceContext,
            ILoggerFactory factory,
            ILifetimeScope container)
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
            services.AddSingleton<IApplicationManager>(this);

            services.AddSingleton(Container);

#if NETCORE10
            services.AddSingleton<IServiceProviderFactory<IServiceCollection>>(new UnityServiceProviderFactory(Container));
#endif
            services.AddSingleton<IStartupFilter>(new UseForwardedHeadersStartupFilter(
                $"{this.Context.ServiceName.AbsoluteUri.Substring("fabric:/".Length)}/{Context.CodePackageActivationContext.CodePackageVersion}", _logger));
           // services.AddSingleton<IStartupFilter>(new ApplicationInsightsStartupFilter1());
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

                    new KestrelCommunicationListener(serviceContext, Options.ServiceEndpointName, (url,listener) =>
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

                            var appInsightKey=Container.Resolve<IOptions<ApplicationInsights>>().Value?.InstrumentationKey;

                            if (!string.IsNullOrEmpty(appInsightKey))
                            {
                                 builder.UseApplicationInsights(appInsightKey);

                                
                            }



                            builder.ConfigureServices((services) =>
                            {
                               // services
                                services.AddSingleton(listener);
                                services.AddSingleton((sp)=> new KestrelHostingAddresss{Url = this.GetAddresses()["kestrel"]  });
                             //   services.AddTransient<TelemetryConfiguration>(sp=>sp.GetRequiredService<IOptions<TelemetryConfiguration>>().Value);
                                services
                                    .AddSingleton<ITelemetryInitializer>((serviceProvider) => FabricTelemetryInitializerExtension.CreateFabricTelemetryInitializer(serviceContext))
                                    .AddSingleton<ITelemetryModule>(new MyServiceRemotingDependencyTrackingTelemetryModule())
                                    .AddSingleton<ITelemetryModule>(new MyServiceRemotingRequestTrackingTelemetryModule())
                                    .AddSingleton<ITelemetryInitializer>(new CodePackageVersionTelemetryInitializer())
                                    .AddSingleton<ITelemetryModule>(new MyTestModule());

                             

                                if (Container.IsRegistered<IConfiguration>())
                                { 
                                    services.AddSingleton((sp)=>Container.Resolve<IConfiguration>());
                                 }

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

//#if NETCORE10
//                            if (Container.IsRegistered<ILoggerFactory>())
//                            {
//                                _logger.LogInformation("UseLoggerFactory for {gatewayKey}", Options.GatewayOptions.Key);
//                                builder.UseLoggerFactory(Container.Resolve<ILoggerFactory>());
//                            }
//#endif

//#if NETCORE20

                            if (Container.IsRegistered<LoggerConfiguration>())
                            {
                                //Container.RegisterType<SerilogLoggerProvider>(new ContainerControlledLifetimeManager(), new InjectionFactory((c) =>
                                //{
                                //     var seriologger =new SerilogLoggerProvider(c.Resolve<Serilog.Core.Logger>(),false);
                                //    return seriologger;

                                //}));
                            
                               
                                builder.ConfigureLogging((hostingContext, logging) =>
                                {
                                  
                                   // logging.AddProvider(Container.Resolve<SerilogLoggerProvider>());
                                    logging.AddFilter("System", LogLevel.Warning);
                                    logging.AddFilter("Microsoft", LogLevel.Warning);
                                    logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Information);
                                  
                          
                                });
                            }
//#endif


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
            //services.AddSingleton<IServiceProviderFactory<ContainerBuilder>>(new AutofacServiceProviderFactory(configurationAction));

            //  builder.UseUnityServiceProvider(Container);
            builder.ConfigureServices((context,services)=> {

                //  services.AddAutofac();
                //  services.AddSingleton<IHostingEnvironment>(context.HostingEnvironment);
                //  services.AddSingleton(sp=>Container.Resolve<ILoggerFactory>())
                // services.AddSingleton(Container.Resolve< IServiceProviderFactory<ContainerBuilder>>());
                services.AddSingleton<IServiceProviderFactory<ContainerBuilder>>(new Test(Container));
             //   services.AddSingleton<IServiceProviderFactory<IServiceCollection>>(new ChildServiceProviderFactory(Container));
            });

            WebBuilderConfiguration?.Invoke(builder);
        }

        protected override async Task OnOpenAsync(CancellationToken cancellationToken)
        {

            try
            {
               


                if (!this.GetAddresses().TryGetValue("kestrel", out string backAddress))
                {

                }

                if (!string.IsNullOrEmpty(Options.ServiceEndpointName))
                {
                    var endpoint = Context.CodePackageActivationContext.GetEndpoint(Options.ServiceEndpointName);
                    backAddress = $"{endpoint.Protocol.ToString().ToLower()}://{Context.NodeContext.IPAddressOrFQDN}:{endpoint.Port}";
                }


                await base.OnOpenAsync(cancellationToken);


                try
                {

                    await RegisterGatewayServiceAsync(backAddress, Options.GatewayOptions);

                    foreach (var gw in Options.AdditionalGateways)
                    {
                        await RegisterGatewayServiceAsync(backAddress, gw);
                    }

                }
                catch (Exception ex)
                {
                 
                    throw;
                }
                //var builder = TelemetryConfiguration.Active.TelemetryProcessorChainBuilder;
                //builder.Use((next) => new AzureRegion(next, "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"));
                //builder.Build();
            }
            catch (Exception ex)
            {


                _logger.LogWarning(new EventId(), ex, "OnOpenAsync failed");
                throw;
            }

        }
        public async Task RestartRequestAsync(CancellationToken cancellationToken)
        {
            var partitionKey = Options.GatewayOptions.Key ?? Context.CodePackageActivationContext.GetServiceManifestName();
            var gateway = ServiceProxy.Create<IGatewayManagementService>(
                new Uri($"fabric:/{Options.GatewayApplicationName??"S-Innovations.ServiceFabric.GatewayApplication"}/GatewayManagementService"), partitionKey.ToPartitionHashFunction());

            await gateway.RestartRequestAsync(partitionKey, cancellationToken);
        }
        protected override async Task RunAsync(CancellationToken cancellationToken)
        {
            var partitionKey = Options.GatewayOptions.Key ?? Context.CodePackageActivationContext.GetServiceManifestName();
            var gateway = ServiceProxy.Create<IGatewayManagementService>(
                new Uri($"fabric:/{Options.GatewayApplicationName??"S-Innovations.ServiceFabric.GatewayApplication"}/GatewayManagementService"), partitionKey.ToPartitionHashFunction());
            

            while (!cancellationToken.IsCancellationRequested)
            {
                if (this.GetAddresses().TryGetValue("kestrel", out string backAddress))
                {


                    var gateways = await gateway.GetGatewayServicesAsync(cancellationToken);

                    if (gateways.Any(gw => gw.Key == partitionKey && gw.IPAddressOrFQDN == Context.NodeContext.IPAddressOrFQDN && gw.BackendPath == backAddress && gw.RestartRequested))
                    {
                        
                        
                            _logger.LogInformation("Restarting {nodeName} {partitionId} {replicationOrInstanceId}", this.Context.NodeContext.NodeName, this.Context.PartitionId, this.Context.ReplicaOrInstanceId);

                            await new FabricClient().ServiceManager.RemoveReplicaAsync(this.Context.NodeContext.NodeName, this.Context.PartitionId, this.Context.ReplicaOrInstanceId); //stateless

                            return;

                    }
                }

                var j = 60;
                while (!cancellationToken.IsCancellationRequested && j --> 0)
                {
                    await Task.Delay(1000);
                }
            }
        }

        private async Task RegisterGatewayServiceAsync(string backAddress, GatewayOptions gw)
        {

            // IGatewayServiceManagerActor gateway = ActorProxy.Create<IGatewayServiceManagerActor>(new ActorId("*"), "S-Innovations.ServiceFabric.GatewayApplication", "GatewayServiceManagerActorService");
            var partitionKey = gw.Key ?? Context.CodePackageActivationContext.GetServiceManifestName();
 
            var gateway = ServiceProxy.Create<IGatewayManagementService>(
                new Uri($"fabric:/{Options.GatewayApplicationName ?? "S-Innovations.ServiceFabric.GatewayApplication"}/GatewayManagementService"),  partitionKey.ToPartitionHashFunction());


                await gateway.RegisterGatewayServiceAsync(new GatewayServiceRegistrationData
                {
                    Key = partitionKey, // $"{partitionKey}-{Context.NodeContext.IPAddressOrFQDN}",
                    IPAddressOrFQDN = Context.NodeContext.IPAddressOrFQDN,
                    ServerName = gw.ServerName,
                    ReverseProxyLocation = gw.ReverseProxyLocation ?? "/",
                    Ssl = gw.Ssl,
                    BackendPath = backAddress,
                    ServiceName = Context.ServiceName,
                    ServiceVersion = Context.CodePackageActivationContext.GetServiceManifestVersion(),
                    CacheOptions = gw.CacheOptions,
                    Properties = gw.Properties
                });
            
        }
    }

    internal class MyTestModule : ITelemetryModule
    {
        public MyTestModule()
        {
        }

        public void Initialize(TelemetryConfiguration configuration)
        {

            configuration.TelemetryChannel.DeveloperMode = false;

            configuration.TelemetryProcessorChainBuilder
            .Use((next) => { return new AggressivelySampleFastRequests(next); })
            
            .Use((next) => { return new AdaptiveSamplingTelemetryProcessor(next); })
            .Build();

        }
    }
    internal class AggressivelySampleFastRequests : ITelemetryProcessor
    {
        private readonly ITelemetryProcessor next;

        private readonly AdaptiveSamplingTelemetryProcessor samplingProcessor;
        private readonly AdaptiveSamplingTelemetryProcessor serviceRemotingProcessor;

        public AggressivelySampleFastRequests(ITelemetryProcessor next)
        {
            this.next = next;
            this.samplingProcessor = new AdaptiveSamplingTelemetryProcessor(this.next); 

            this.serviceRemotingProcessor = new AdaptiveSamplingTelemetryProcessor(this.next)
            {
                ExcludedTypes = "Event", // exclude custom events from being sampled
                MaxTelemetryItemsPerSecond = 1, // default: 5 calls/sec
                SamplingPercentageIncreaseTimeout = TimeSpan.FromSeconds(30), // default: 2 min
                SamplingPercentageDecreaseTimeout = TimeSpan.FromSeconds(10), // default: 30 sec
                EvaluationInterval = TimeSpan.FromSeconds(10), // default: 15 sec
                InitialSamplingPercentage = 25, // default: 100%
            };
        }

        public void Process(ITelemetry item)
        {
            if (!string.IsNullOrEmpty(item.Context.Operation.SyntheticSource)) { return; }

            if (item is DependencyTelemetry dependency && dependency.Duration.TotalMilliseconds < 350)
            {
                return;
            }
            // check the telemetry type and duration
            if (item is RequestTelemetry d)
            {
                if (d.Context.GetInternalContext().SdkVersion.StartsWith("serviceremoting"))
                {
                    if(d.Duration < TimeSpan.FromMilliseconds(50))
                    {
                        return;
                    } 

                    this.serviceRemotingProcessor.Process(item);
                    return;
                }
                if (d.Duration < TimeSpan.FromMilliseconds(200))
                {
                    // let sampling processor decide what to do
                    // with this fast incoming request
                    this.samplingProcessor.Process(item);
                    return;
                }
            }

            if (item is TraceTelemetry trace)
            {
                if (trace.Properties.TryGetValue("SourceContext", out var category) &&
                    category == "Microsoft.AspNetCore.StaticFiles.StaticFileMiddleware")
                {
                    return;
                }
            }


            // in all other cases simply call next
            this.next.Process(item);
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
            ILifetimeScope container)
            : base(options, serviceContext, factory, container)
        {

        }

        public override void ConfigureBuilder(IWebHostBuilder builder)
        {
            base.ConfigureBuilder(builder);
            builder.UseStartup<TStartUp>();
        }
    }

    
}
