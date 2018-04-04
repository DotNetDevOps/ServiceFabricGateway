using Microsoft.ServiceFabric.Actors;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using SInnovations.ServiceFabric.Gateway.Common.Model;
using SInnovations.ServiceFabric.Gateway.Model;
using System;
using System.Threading;
using System.Threading.Tasks;

//[assembly: FabricTransportActorRemotingProvider(RemotingListener = RemotingListener.V2Listener, RemotingClient = RemotingClient.V2Client)]

[assembly: FabricTransportServiceRemotingProvider(RemotingListener = RemotingListener.V2Listener, RemotingClient = RemotingClient.V2Client)]

namespace SInnovations.ServiceFabric.Gateway.Actors
{



    public interface IGatewayManagementService : IService
    {

        /// <summary>
        /// Register a backend service to be configured to receive requests from the proxy.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        Task RegisterGatewayServiceAsync(GatewayServiceRegistrationData data);

        Task RequestCertificateAsync(string hostname, SslOptions options, bool force );
        Task<CertGenerationState> GetCertGenerationInfoAsync(string hostname, CancellationToken token);
        Task<GatewayServiceRegistrationData[]> GetGatewayServicesAsync(CancellationToken cancellationToken);
        Task<DateTimeOffset> GetLastUpdatedAsync(CancellationToken token);
        Task<string> GetChallengeResponseAsync(string hostname,CancellationToken requestAborted);
        Task SetupStorageServiceAsync(int instanceCount);
    }

    //public interface IGatewayServiceManagerActor : IActor
    //{
    //    /// <summary>
    //    /// Register a backend service to be configured to receive requests from the proxy.
    //    /// </summary>
    //    /// <param name="data"></param>
    //    /// <returns></returns>
    //  //  Task RegisterGatewayServiceAsync(GatewayServiceRegistrationData data);  

    //    /// <summary>
    //    /// Get all registered Proxies
    //    /// </summary>
    //    /// <returns></returns>

    // //   Task<List<GatewayServiceRegistrationData>> GetGatewayServicesAsync();
    //    /// <summary>
    //    /// Get the last time an update was made that should cause configuration files to be rewritten
    //    /// </summary>
    //    /// <returns></returns>
    // //   Task<DateTimeOffset> GetLastUpdatedAsync();

    //    /// <summary>
    //    /// Check if a certificate is ready for the given hostname, if not the certificate will be requested for later checks.
    //    /// </summary>
    //    /// <param name="hostname"></param>
    //    /// <param name="options"></param>
    //    /// <returns></returns>
    //   // Task<bool> IsCertificateAvaibleAsync(string hostname, SslOptions options);
    //    Task RequestCertificateAsync(string hostname, SslOptions options);

    //    Task SetupStorageServiceAsync(int instanceCount);

    //    Task SetLastUpdatedNow();
    //}
}
