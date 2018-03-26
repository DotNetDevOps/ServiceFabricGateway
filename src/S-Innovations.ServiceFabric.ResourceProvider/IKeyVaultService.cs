using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using System.Threading.Tasks;

 
namespace SInnovations.ServiceFabric.ResourceProvider
{
    public interface IKeyVaultService : IService
    {
        Task<string> GetSecretAsync(string key);
    }

    public interface IAzureADTokenService : IService
    {
        Task<string> GetTokenAsync();
    }

}
