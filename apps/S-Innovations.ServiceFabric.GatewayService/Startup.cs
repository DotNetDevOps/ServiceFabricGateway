﻿using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.ServiceFabric.Services.Client;
using Microsoft.ServiceFabric.Services.Communication.Client;
using Microsoft.ServiceFabric.Services.Remoting.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SInnovations.ServiceFabric.Gateway.Actors;
using SInnovations.ServiceFabric.Gateway.Communication;
using SInnovations.ServiceFabric.Gateway.Model;
using SInnovations.ServiceFabric.GatewayService.Services;
using System;
using System.Collections.Generic;
using System.Fabric;
using System.Linq;
using System.Threading.Tasks;
using Unity;
using SInnovations.ServiceFabric.Gateway.Common.Extensions;

//[assembly: FabricTransportServiceRemotingProvider(RemotingListener = RemotingListener.V2Listener, RemotingClient = RemotingClient.V2Client)]
//[assembly: FabricTransportActorRemotingProvider(RemotingListener = RemotingListener.V2Listener, RemotingClient = RemotingClient.V2Client)]

namespace SInnovations.ServiceFabric.GatewayService
{
    public class ServiceProviderInfomation : GatewayServiceInformation
    {
        public Uri ServiceUri { get; set; }

        public TargetReplicaSelector TargetReplicaSelector { get; set; }

        public string ListenerName { get; set; }

        public OperationRetrySettings OperationRetrySettings { get; set; }

        public Func<HttpContext, ServicePartitionKey> GetServicePartitionKey { get; set; }
    }
    public class HttpGatewayServiceManager
    {
        private static readonly FabricClient FabricClient = new FabricClient();
        private static readonly HttpCommunicationClientFactory CommunicationFactory = new HttpCommunicationClientFactory(new ServicePartitionResolver(() => FabricClient));

        public List<ServiceProviderInfomation> Providers { get; set; } = new List<ServiceProviderInfomation>();

        public ServiceProviderInfomation ResolveGatewayServiceInfomation(HttpContext context, bool updatePathBase)
        {
            var options = Providers.FirstOrDefault(p => context.Request.Path.StartsWithSegments(p.PathPrefix));

            if (options != null && updatePathBase)
            {
                //Move the part of the path that is matched to PathBase;
                context.Request.PathBase = context.Request.PathBase + options.PathPrefix;
                context.Request.Path = context.Request.Path.Value.Substring(options.PathPrefix.Length);
            }

            return options;
        }


        public ServiceProviderInfomation ResolveGatewayServiceInfomationAndUpdateRequestPath(HttpContext context)
        {
            return ResolveGatewayServiceInfomation(context, true);
        }

        public bool HasGatewayServiceInfomation(HttpContext context)
        {
            return ResolveGatewayServiceInfomation(context, false) != null;
        }

        public async Task InitializeAsync()
        {
            //Providers.Add(new ServiceProviderInfomation
            //{

            //    ServiceUri = new Uri("fabric:/S-Innovations.Identity.ServiceFabricApplication/IdSvr4Service", UriKind.Absolute),
            //    OperationRetrySettings = new OperationRetrySettings(TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2), 30)
            //});

            foreach (var sfApp in await FabricClient.QueryManager.GetApplicationListAsync())
            {
                foreach (var sfService in await FabricClient.QueryManager.GetServiceListAsync(sfApp.ApplicationName))
                {

                    //   var serv = await fabric.ServiceManager.GetServiceDescriptionAsync(sfService.ServiceName);

                    var partitionClient = new ServicePartitionClient<HttpCommunicationClient>(CommunicationFactory, sfService.ServiceName);

                    var data = await partitionClient.InvokeWithRetryAsync(async (client) =>
                      {
                          var rsp = await client.GetAsync("/sf-gateway-metadata");
                          var str = await rsp.Content.ReadAsStringAsync();
                          try
                          {
                              return JsonConvert.DeserializeObject<ServiceProviderInfomation>(str);
                          }
                          catch (Exception)
                          {
                              return null;
                          }
                      });
                    if (data != null)
                    {
                        data.ServiceUri = sfService.ServiceName;

                        data.OperationRetrySettings = new OperationRetrySettings(TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2), 30);
                        Providers.Add(data);
                    }





                    //   ServicePartitionResolver resolver = ServicePartitionResolver.GetDefault();

                    //  ResolvedServicePartition partition =
                    //    await resolver.ResolveAsync(sfService.ServiceName, new ServicePartitionKey(), CancellationToken.None);
                    //   await context.Response.WriteAsync(partition.Info.Id + " , " + partition.Info.Kind);
                    //   await context.Response.WriteAsync(Environment.NewLine);
                    // foreach (var endpoint in partition.Endpoints)
                    // {
                    //  await context.Response.WriteAsync("\t" + endpoint.Address + ", " + endpoint.Role + Environment.NewLine);
                    // }

                    //       await context.Response.WriteAsync(await fabric.ServiceManager.GetServiceManifestAsync(sfApp.ApplicationTypeName,sfApp.ApplicationTypeVersion,))

                }

            }
        }

    }

    public class AlwaysTreatedAsNonTransientExceptionHandler : IExceptionHandler
    {
        public bool TryHandleException(ExceptionInformation exceptionInformation, OperationRetrySettings retrySettings, out ExceptionHandlingResult result)
        {
            if (exceptionInformation == null)
            {
                throw new ArgumentNullException(nameof(exceptionInformation));
            }

            if (retrySettings == null)
            {
                throw new ArgumentNullException(nameof(retrySettings));
            }

            result = new ExceptionHandlingRetryResult(exceptionInformation.Exception, false, retrySettings, retrySettings.DefaultMaxRetryCount);

            return true;
        }
    }
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddHttpRequestDispatcherProvider(this IServiceCollection services, HttpCommunicationClientFactory provider)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (provider == null)
            {
                throw new ArgumentNullException(nameof(provider));
            }

            services.AddSingleton(provider);

            return services;
        }

        public static IServiceCollection AddDefaultHttpRequestDispatcherProvider(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddHttpRequestDispatcherProvider(new HttpCommunicationClientFactory(null, new[] { new AlwaysTreatedAsNonTransientExceptionHandler() }, null));

            return services;
        }
    }

    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            var provider = new HttpGatewayServiceManager();
            //   provider.InitializeAsync();

            services.AddSingleton(provider);
            services.AddDefaultHttpRequestDispatcherProvider();

            services.AddRouting();

            services.AddCors(o => o.AddPolicy("GatewayManagement", c => c.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin()));
            
        }
        public void ConfigureContainer(IUnityContainer container)
        {
            container.RegisterInstance("This string is displayed if container configured correctly",
                                       "This string is displayed if container configured correctly");


        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
          //  loggerFactory.AddConsole();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            //var telemetryConfiguration = app.ApplicationServices.GetService<TelemetryConfiguration>();
            //var builder = telemetryConfiguration.TelemetryProcessorChainBuilder;

            //builder.Use((next) => new CustomTelemetryProcessor(next));
            //builder.Build();

            app.UseCors("GatewayManagement");

            app.UseRouter(router =>
            {
                router.MapGet("services", async (HttpContext context) =>
                {
                    var a = context.RequestServices.GetService<NginxGatewayService>();

                    await context.Response.WriteAsync(JToken.FromObject(await a.GetGatewayServicesAsync(context.RequestAborted)).ToString(Formatting.Indented));
                });
                //router.MapPost("services/update", async (context) =>
                //{
                //    var a = context.RequestServices.GetService<NginxGatewayService>();
                // //   await a.SetLastUpdatedAsync(DateTimeOffset.UtcNow,context.RequestAborted);
                //});
                //router.MapDelete("services/{key}", async (context) =>
                //{
                //    var a = context.RequestServices.GetService<NginxGatewayService>();
                //    var routeData = context.GetRouteData();

                //    await a.DeleteGatewayServiceAsync(context.GetRouteValue("key") as string, context.RequestAborted);

                //    context.Response.StatusCode = 204;
                //});

                router.MapGet(".well-known/acme-challenge/{token}", async (request,response,route)=>
                {
                    
                    {
                        //var _fabricClient = new FabricClient();
                        var loggerfactory = request.HttpContext.RequestServices.GetService<ILoggerFactory>();
                        var logger = loggerfactory.CreateLogger("acme-challenge");

                        logger.LogInformation("Acme-Challenge request for {Host}", request.Host.Host);

                        var codeContext = request.HttpContext.RequestServices.GetService<ICodePackageActivationContext>();
                        logger.LogInformation("Acme-Challenge request for {host} using {Context}", request.Host.Host,codeContext);

                        var applicationName = codeContext.ApplicationName;

                        logger.LogInformation("Acme-Challenge request for {host} with {applicationName}", request.Host.Host, applicationName);

                        var actorServiceUri = new Uri($"{applicationName}/{nameof(GatewayManagementService)}");
                        var actorservice = ServiceProxy.Create<IGatewayManagementService>(actorServiceUri, request.Host.Host.ToPartitionHashFunction());

                        var keyAuthString = await actorservice.GetChallengeResponseAsync(request.Host.Host,request.HttpContext.RequestAborted);

                        logger.LogInformation("Acme-Challenge request for {host} with {applicationName} returns {keyAuthString}", request.Host.Host, applicationName, keyAuthString);

                        response.ContentType = "plain/text";
                        await response.WriteAsync(keyAuthString);

                        // var actor = ActorProxy.Create<IGatewayServiceManagerActor>(new ActorId("local.earthml.com"))
                        //var partitions = new List<long>();
                        //var servicePartitionList = await _fabricClient.QueryManager.GetPartitionListAsync(actorServiceUri);
                        //foreach (var servicePartition in servicePartitionList)
                        //{
                        //    var partitionInformation = servicePartition.PartitionInformation as Int64RangePartitionInformation;
                        //    partitions.Add(partitionInformation.LowKey);
                        //}

                        //var serviceProxyFactory = new ServiceProxyFactory();

                        //var actors = new Dictionary<long, DateTimeOffset>();
                        //foreach (var partition in partitions)
                        //{
                        //    var actorService = serviceProxyFactory.CreateServiceProxy<IGatewayServiceManagerActorService>(actorServiceUri, new ServicePartitionKey(partition));

                        //    CertGenerationState[] certs = await actorService.GetCerts(request.HttpContext.RequestAborted);


                        //}




                    }
                });
            });
  
            

            app.UseWelcomePage();

        }
    }

    //internal class CustomTelemetryProcessor : ITelemetryProcessor
    //{
    //    private ITelemetryProcessor next;

    //    public CustomTelemetryProcessor(ITelemetryProcessor next)
    //    {
    //        this.next = next;
    //    }

    //    public void Process(ITelemetry item)
    //    {
    //        if(item is TraceTelemetry trace && request.)
    //        {
                
    //        }

    //        next.Process(item);
    //    }
    //}
}
