using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using SInnovations.Azure.MessageProcessor.ServiceBus;

 

namespace SInnovations.ServiceFabric.ResourceProvider
{
    public interface IMessageBusCorrelationFactory
    {
        (string key, EntityDescription value) Create();
    }

}
