using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using SInnovations.Azure.MessageProcessor.Core;
using System;

 

namespace SInnovations.ServiceFabric.ResourceProvider
{
    [Serializable]
    public class ProviderMessage : BaseMessage, IResourceProviderBaseMessage
    {
        public string ProviderId { get; set; }
    }

}
