using System;
using System.Fabric;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.Client;
using SInnovations.ServiceFabric.Gateway.Common.Extensions;
using Microsoft.ServiceFabric.Services.Remoting.V2.FabricTransport.Client;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using Polly.Retry;
using Polly;
using SInnovations.ServiceFabric.GatewayService.Services;
using Microsoft.ServiceFabric.Services.Client;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{
    //public class CloudFlareZoneService : ICloudFlareZoneService
    //{
    //    public CloudFlareZoneService()
    //    {

    //    }
    //    private readonly Dictionary<string, string> _zones = new Dictionary<string, string>();
    //    public Task<string> GetZoneIdAsync(string dnsIdentifier)
    //    {
    //        var domain = string.Join(".", dnsIdentifier.Split(".").TakeLast(2)).ToLower();
    //        if (_zones.ContainsKey(domain))
    //            return Task.FromResult(_zones[dnsIdentifier]);
    //        return Task.FromResult(string.Empty);
    //    }

    //    public Task UpdateZoneIdAsync(string v1, string v2)
    //    {
    //        _zones[v1] = v2;
    //        return Task.CompletedTask;
    //    }
    //}
    public class GatewayManagementServiceClient
    {
        private readonly ICodePackageActivationContext codePackageActivationContext;

        public GatewayManagementServiceClient(ICodePackageActivationContext codePackageActivationContext)
        {
            this.codePackageActivationContext = codePackageActivationContext;
        }
        public static TimeSpan TimeoutSpan = TimeSpan.FromSeconds(10);

        public static AsyncRetryPolicy TimeOutRetry= Policy
              .Handle<TimeoutException>()
              .WaitAndRetryAsync(
                5, 
                retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)), 
                (exception, timeSpan, context) => {
                  // do something
                }
              );
        protected T GetProxy<T>(string partition) where T:IService => CreateProxyFactoryFabricTransport().CreateServiceProxy<T>(new Uri($"{codePackageActivationContext.ApplicationName}/{nameof(GatewayManagementService)}"), partition.ToPartitionHashFunction());

        public static T GetProxy<T>(string service,string partition) where T : IService => CreateProxyFactoryFabricTransport().CreateServiceProxy<T>(new Uri(service), partition.ToPartitionHashFunction());
        public static T GetProxy<T>(Uri service, ServicePartitionKey partition) where T : IService => CreateProxyFactoryFabricTransport().CreateServiceProxy<T>(service, partition);


        public static IServiceProxyFactory CreateProxyFactoryFabricTransport()
        {


          //  var settings = new FabricTransportRemotingSettings();

         
            return new ServiceProxyFactory(
                (h) =>
                {
                    var settings = new FabricTransportRemotingSettings();
                    settings.UseWrappedMessage = true;
                    settings.OperationTimeout = TimeSpan.FromMinutes(1);
                    return new FabricTransportServiceRemotingClientFactory(settings);
                });

        }
    }










}
