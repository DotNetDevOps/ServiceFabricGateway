using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Rest;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using SInnovations.Azure.MessageProcessor.Core;
using SInnovations.Azure.MessageProcessor.ServiceBus;
using SInnovations.ServiceFabric.Gateway.Common.Services;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace SInnovations.ServiceFabric.ResourceProvider
{
   
    public class MessageBusOptions
    {
        public Guid SubscriptionId { get; set; }
        public string ResourceGroup { get; set; }
        public string Namespace { get; set; }
        public string AuthorizationRuleName { get; set; } = "RootManageSharedAccessKey";
    }
    public class MessageBus : IMessageBus, IDisposable
    {
        private readonly AsyncLazy<ServiceBusMessageProcessorClientProvider> bus;
        private readonly MessageBusOptions options;
        private readonly IAzureADTokenService keyVaultService;
        private readonly ILoggerFactory loggerFactory;
        private readonly IMessageBusCorrelationFactory[] correlations;
        private readonly ActionBlock<ProviderMessage> _pipeline;

        public MessageBus(IOptions<MessageBusOptions> options, IAzureADTokenService keyVaultService ,ILoggerFactory loggerFactory, IMessageBusCorrelationFactory[] correlations)
        {
            this.options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            this.keyVaultService = keyVaultService ?? throw new ArgumentNullException(nameof(keyVaultService));
            this.loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
            this.correlations = correlations ?? throw new ArgumentNullException(nameof(correlations));

            bus = new AsyncLazy<ServiceBusMessageProcessorClientProvider>((Func< Task < ServiceBusMessageProcessorClientProvider > >)Factory);
            bus.Start();

            _pipeline = new ActionBlock<ProviderMessage>(async (message) =>
             {
                 var sender = await bus;

                 await sender.SendMessageAsync(message);

             }, new ExecutionDataflowBlockOptions { MaxDegreeOfParallelism = 4 });


        }
   

        private async Task<ServiceBusMessageProcessorClientProvider> Factory() {


            var client = new Microsoft.Azure.Management.ServiceBus.ServiceBusManagementClient(new TokenCredentials(await keyVaultService.GetTokenAsync()));
            client.SubscriptionId = options.SubscriptionId.ToString();


            var conn = await client.Namespaces.ListKeysWithHttpMessagesAsync(options.ResourceGroup,options.Namespace,options.AuthorizationRuleName);

            var correlationsMap = new Dictionary<string, EntityDescription>
                      {
                          { "default",  new QueueDescription("earthml-default") },
                          { "EarthML.Identity",  new QueueDescription("earthml-identity") },
                          { "EarthML.Pimetr",  new QueueDescription("earthml-pimetr") },
                          { "EarthML.Notifications", new TopicDescription("signalr") }
                      };

            foreach (var correlation in correlations)
            {
                var(key, value) = correlation.Create();
                correlationsMap.Add(key, value);
            }

            return  new ServiceBusMessageProcessorProvider(loggerFactory,
                new ServiceBusMessageProcessorProviderOptions
                {
                    ConnectionString = conn.Body.PrimaryConnectionString,
                    TopicScaleCount = 2,
                    TopicDescription = new TopicDescription("earthml-documents"),
                    SubscriptionDescription = new SubscriptionDescription("earthml-documents", "sub"),
                    CorrelationToQueueMapping = correlationsMap,
                    CorrelationIdProvider = CorrelationIdProvider
                });
        }

        
        public Task SendAsync(ProviderMessage message)
        {
            return _pipeline.SendAsync(message);
        }

        private static ConcurrentDictionary<Type, string> _providers = new ConcurrentDictionary<Type, string>();
        private static string CorrelationIdProvider(BaseMessage arg)
        {

            if (arg is IResourceProviderBaseMessage message)
            {
                return message.ProviderId ?? _providers.GetOrAdd(arg.GetType(),(type)=>type.GetCustomAttribute< ResourceProviderAttribute>()?.ProviderNamespace ?? "default");
            }

            return _providers.GetOrAdd(arg.GetType(), (type) => type.GetCustomAttribute<ResourceProviderAttribute>()?.ProviderNamespace ?? "default");


        }

        public void Dispose()
        {
            _pipeline.Complete();
            _pipeline.Completion.Wait();
        }
    }

}
