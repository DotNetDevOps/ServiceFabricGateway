using Microsoft.ServiceFabric.Services.Client;
using Microsoft.ServiceFabric.Services.Communication.Client;
using System;
using System.Collections.Generic;
using System.Fabric;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
namespace SInnovations.ServiceFabric.Gateway.Communication
{
    public class HttpCommunicationServicePartitionClientFactory
    {
        private readonly IHttpClientFactory provider;
        private readonly FabricClient fabricClient;

        public HttpCommunicationServicePartitionClientFactory(IHttpClientFactory provider, FabricClient fabricClient)
        {
            this.provider = provider;
            this.fabricClient = fabricClient;
        }
        public HttpCommunicationServicePartitionClient Create(Uri application, Uri serviceUri,  ServicePartitionKey partitionKey = null, TargetReplicaSelector targetReplicaSelector = TargetReplicaSelector.Default, string listenerName = null, OperationRetrySettings retrySettings = null)
        {
            return new HttpCommunicationServicePartitionClient(factory, fabricClient, application,serviceUri, partitionKey, targetReplicaSelector, listenerName, retrySettings);

        }

        private async Task<HttpCommunicationClient> factory(string endpoint, Uri application, Uri serviceUri)
        {
            var http = provider.CreateClient(endpoint);

            var services = await fabricClient.QueryManager.GetServiceListAsync(application, serviceUri).ConfigureAwait(false);
            var service = services.FirstOrDefault();
            var key = $"{serviceUri.AbsoluteUri.Substring("fabric:/".Length)}/{service.ServiceManifestVersion}";

            http.DefaultRequestHeaders.Add("X-ServiceFabric-Key", key);
            http.BaseAddress = new Uri(endpoint, UriKind.Absolute);

            return new HttpCommunicationClient(http);
        }

     
    }


    public class HttpCommunicationServicePartitionClient : ServicePartitionClient<HttpCommunicationClient>
    {
       

        //  private readonly FabricClient fabricClient;
       // private readonly Uri application;
        
        public HttpCommunicationServicePartitionClient(Func<string,Uri,Uri, Task<HttpCommunicationClient>> innerDispatcherProvider, FabricClient fabricClient,
           Uri application, Uri serviceUri, ServicePartitionKey partitionKey = null, TargetReplicaSelector targetReplicaSelector = TargetReplicaSelector.Default, string listenerName = null, OperationRetrySettings retrySettings = null)
            : base(new HttpCommunicationClientFactory((endpoint)=> innerDispatcherProvider(endpoint, application, serviceUri), new ServicePartitionResolver(() => fabricClient)), serviceUri, partitionKey, targetReplicaSelector, listenerName, retrySettings)
        {
           

            // this.fabricClient = fabricClient;
           // this.application = application;
           
        }

       

        public string BearerToken { get; set; }


        public Task<HttpResponseMessage> GetAsync(string pathAndQuery)
        {
            return InvokeWithRetryAsync(async (client) =>
            {
                if (!string.IsNullOrEmpty(BearerToken))
                {
                    client.HttpClient.DefaultRequestHeaders.Authorization = 
                        new AuthenticationHeaderValue("Bearer", BearerToken);
                }
              
               


                HttpResponseMessage response = await client.HttpClient.GetAsync(new Uri(client.HttpClient.BaseAddress, pathAndQuery));
                return response;
            });
        }



    }

    public class HttpCommunicationClientFactory : CommunicationClientFactoryBase<HttpCommunicationClient>
    {
        private readonly Func<string,Task<HttpCommunicationClient>> _innerDispatcherProvider;

        //public HttpCommunicationClientFactory(IHttpClientFactory provider, IServicePartitionResolver servicePartitionResolver = null, IEnumerable<IExceptionHandler> exceptionHandlers = null, string traceId = null)
        //    : this((endpoint) => provider.CreateClient(endpoint), servicePartitionResolver, exceptionHandlers, traceId)
        //{          
        //}

        public HttpCommunicationClientFactory(Func<string,Task<HttpCommunicationClient>> innerDispatcherProvider, IServicePartitionResolver servicePartitionResolver = null, IEnumerable<IExceptionHandler> exceptionHandlers = null, string traceId = null)
            : base(servicePartitionResolver, exceptionHandlers, traceId)
        {
            _innerDispatcherProvider = innerDispatcherProvider ?? throw new ArgumentNullException(nameof(innerDispatcherProvider));
        }

        protected override void AbortClient(HttpCommunicationClient dispatcher)
        {
            if (dispatcher != null)
            {
                dispatcher.HttpClient.Dispose();
            }
        }

        protected override Task<HttpCommunicationClient> CreateClientAsync(string endpoint, CancellationToken cancellationToken)
        {

            return _innerDispatcherProvider.Invoke(endpoint);
        }

        protected override bool ValidateClient(HttpCommunicationClient dispatcher)
        {
            return dispatcher != null && dispatcher.HttpClient.BaseAddress != null;
        }

        protected override bool ValidateClient(string endpoint, HttpCommunicationClient dispatcher)
        {
            return dispatcher != null && dispatcher.HttpClient.BaseAddress == new Uri(endpoint, UriKind.Absolute);
        }
    }
}
