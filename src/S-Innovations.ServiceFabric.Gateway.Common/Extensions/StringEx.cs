using Microsoft.ServiceFabric.Actors;
using Microsoft.ServiceFabric.Actors.Remoting.FabricTransport;
using Microsoft.ServiceFabric.Services.Client;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using SInnovations.ServiceFabric.Gateway.Common.Model;
using SInnovations.ServiceFabric.Gateway.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

//[assembly: FabricTransportServiceRemotingProvider(RemotingListener = RemotingListener.V2Listener, RemotingClient = RemotingClient.V2Client)]


namespace SInnovations.ServiceFabric.Gateway.Common.Extensions
{
    //public interface IGatewayServiceManagerActorService : IService
    //{
    //    Task<Dictionary<ActorId, DateTimeOffset>> GetLastUpdatedAsync(CancellationToken cancellationToken);
    //    Task<CertGenerationState> GetCertGenerationInfoAsync(string hostname, SslOptions options, CancellationToken cancellationToken);

    //    Task<List<GatewayServiceRegistrationData>> GetGatewayServicesAsync(CancellationToken cancellationToken);
    //    Task DeleteGatewayServiceAsync(string key, CancellationToken cancellationToken);
    //    Task<CertGenerationState[]> GetCerts(CancellationToken requestAborted);
    //    Task<string> GetChallengeResponseAsync(ActorId actorId, CancellationToken requestAborted);
    //}
    public static class StringEx
    {
        public static ServicePartitionKey ToPartitionHashFunction(this string partitionKey)
        {
            var md5 = MD5.Create();
            var value = md5.ComputeHash(Encoding.ASCII.GetBytes(partitionKey));
            var key = BitConverter.ToInt64(value, 0);
            return new ServicePartitionKey(key);
        }
    }
}
