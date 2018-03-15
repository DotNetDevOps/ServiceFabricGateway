using Microsoft.Extensions.Logging;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using SInnovations.Azure.MessageProcessor.Core;
using SInnovations.Azure.MessageProcessor.ServiceBus;
using System.Collections.Generic;
using System.Threading.Tasks;

 

namespace SInnovations.ServiceFabric.ResourceProvider
{
    public class MessageBus : IMessageBus
    {
        private readonly ServiceBusMessageProcessorClientProvider bus;

        public MessageBus(ILoggerFactory loggerFactory, IMessageBusCorrelationFactory[] correlations)
        {

            var correlationsMap = new Dictionary<string, EntityDescription>
                      {
                          { "default",  new QueueDescription("earthml-default") },
                          { "EarthML.Identity",  new QueueDescription("earthml-identity") }
                      };

            foreach (var correlation in correlations)
            {
                var (key, value) = correlation.Create();
                correlationsMap.Add(key, value);
            }

            this.bus = new ServiceBusMessageProcessorProvider(loggerFactory,
                new ServiceBusMessageProcessorProviderOptions
                {
                    ConnectionString = "Endpoint=sb://pimetr-test.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=hneK2rrAHKtcXOpx0B3qPNfT1vMtSBX5LtMQNP5tERE=",
                    TopicScaleCount = 2,
                    TopicDescription = new TopicDescription("earthml-documents"),
                    SubscriptionDescription = new SubscriptionDescription("earthml-documents", "sub"),
                    CorrelationToQueueMapping = correlationsMap,
                    CorrelationIdProvider = CorrelationIdProvider
                });
        }


        public Task PublishAsync(ProviderMessage message)
        {
            return bus.SendMessageAsync(message);
        }

        private static string CorrelationIdProvider(BaseMessage arg)
        {
            if (arg is IResourceProviderBaseMessage message)
            {
                return message.ProviderId;
            }

            return "default";


        }

    }

}
