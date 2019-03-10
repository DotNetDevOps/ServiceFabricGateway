using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.ResourceProvider
{
    public interface IMessageBus
    {
        Task SendAsync(ProviderMessage message);

    }

}
