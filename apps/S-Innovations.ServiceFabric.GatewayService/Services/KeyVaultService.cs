using Microsoft.Extensions.Configuration;
using Microsoft.ServiceFabric.Actors;
using Microsoft.ServiceFabric.Actors.Query;
using Microsoft.ServiceFabric.Actors.Runtime;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Remoting.Runtime;
using Microsoft.ServiceFabric.Services.Runtime;
using SInnovations.ServiceFabric.Gateway.Common.Model;
using SInnovations.ServiceFabric.Gateway.Model;
using SInnovations.ServiceFabric.ResourceProvider;
using SInnovations.ServiceFabric.Storage.Configuration;
using System;
using System.Collections.Generic;
using System.Fabric;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.GatewayService.Services
{
    public class KeyVaultService : StatelessService, IKeyVaultService, IAzureADTokenService
    {
        private readonly IConfigurationRoot configuration;
        private readonly AzureADConfiguration azureAD;

        public KeyVaultService(StatelessServiceContext serviceContext, IConfigurationRoot configuration, AzureADConfiguration azureAD) : base(serviceContext)
        {
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.azureAD = azureAD;
        }



        protected override IEnumerable<ServiceInstanceListener> CreateServiceInstanceListeners()
        {
            return this.CreateServiceRemotingInstanceListeners();
        }


        public Task<string> GetSecretAsync(string key)
        {
            var value = configuration.GetSection("KeyVault:" + key).Value;
            if (string.IsNullOrEmpty(value))
            {
                configuration.Reload();
            }

            return Task.FromResult(value);
        }

        public Task<string> GetTokenAsync()
        {
            return this.azureAD.GetAccessToken();
        }

        public Task<string> GetTokenAsync(string resource)
        {
            return this.azureAD.GetTokenFromClientSecret(string.Empty, resource);
        }
    }

    //public class GatewayServiceManagerActorService : ActorService//, IGatewayServiceManagerActorService
    //{
    //    public GatewayServiceManagerActorService(
    //        StatefulServiceContext context,
    //        ActorTypeInformation actorTypeInfo,
    //        Func<ActorService, ActorId, ActorBase> actorFactory = null,
    //        Func<ActorBase, IActorStateProvider, IActorStateManager> stateManagerFactory = null,
    //        IActorStateProvider stateProvider = null, ActorServiceSettings settings = null)
    //        : base(context, actorTypeInfo, actorFactory, stateManagerFactory, stateProvider, settings)
    //    {

    //    }
    //    //protected override IEnumerable<ServiceReplicaListener> CreateServiceReplicaListeners()
    //    //{
    //    //    return this.CreateServiceRemotingReplicaListeners();
    //    //}


    //    public async Task DeleteGatewayServiceAsync(string key, CancellationToken cancellationToken)
    //    {
    //        ContinuationToken continuationToken = null;

    //        do
    //        {

    //            var page = await this.StateProvider.GetActorsAsync(100, continuationToken, cancellationToken);

    //            foreach (var actor in page.Items)
    //            {
    //                if (await this.StateProvider.ContainsStateAsync(actor, GatewayServiceManagerActor.STATE_PROXY_DATA_NAME, cancellationToken))
    //                {
    //                    var registrations = await this.StateProvider.LoadStateAsync<List<GatewayServiceRegistrationData>>(actor, GatewayServiceManagerActor.STATE_PROXY_DATA_NAME, cancellationToken);

    //                    if (registrations.RemoveAll(registration => registration.Key == key) > 0)
    //                    {
    //                        var changes = new ActorStateChange(
    //                                GatewayServiceManagerActor.STATE_PROXY_DATA_NAME,
    //                                typeof(List<GatewayServiceRegistrationData>),
    //                                registrations, StateChangeKind.Update);
    //                        var time = new ActorStateChange(
    //                            GatewayServiceManagerActor.STATE_LAST_UPDATED_NAME, typeof(DateTimeOffset), DateTimeOffset.UtcNow, StateChangeKind.Update);


    //                        await this.StateProvider.SaveStateAsync(actor, new[] { changes, time }, cancellationToken);


    //                    }
    //                }
    //            }

    //            continuationToken = page.ContinuationToken;
    //        }
    //        while (continuationToken != null);

    //    }
    //    public async Task<List<GatewayServiceRegistrationData>> GetGatewayServicesAsync(CancellationToken cancellationToken)
    //    {
    //        ContinuationToken continuationToken = null;
    //        var all = new List<GatewayServiceRegistrationData>();

    //        do
    //        {

    //            var page = await this.StateProvider.GetActorsAsync(100, continuationToken, cancellationToken);

    //            foreach (var actor in page.Items)
    //            {
    //                if (await this.StateProvider.ContainsStateAsync(actor, GatewayServiceManagerActor.STATE_PROXY_DATA_NAME, cancellationToken))
    //                {
    //                    var count = await this.StateProvider.LoadStateAsync<List<GatewayServiceRegistrationData>>(actor, GatewayServiceManagerActor.STATE_PROXY_DATA_NAME, cancellationToken);
    //                    all.AddRange(count);
    //                }
    //            }

    //            continuationToken = page.ContinuationToken;
    //        }
    //        while (continuationToken != null);

    //        return all;
    //    }

    //    public async Task<Dictionary<ActorId, DateTimeOffset>> GetLastUpdatedAsync(CancellationToken cancellationToken)
    //    {
    //        ContinuationToken continuationToken = null;
    //        var actors = new Dictionary<ActorId, DateTimeOffset>();

    //        do
    //        {

    //            var page = await this.StateProvider.GetActorsAsync(100, continuationToken, cancellationToken);

    //            foreach (var actor in page.Items)
    //            {
    //                if (await this.StateProvider.ContainsStateAsync(actor, GatewayServiceManagerActor.STATE_LAST_UPDATED_NAME, cancellationToken))
    //                {
    //                    var count = await this.StateProvider.LoadStateAsync<DateTimeOffset>(actor, GatewayServiceManagerActor.STATE_LAST_UPDATED_NAME, cancellationToken);
    //                    actors.Add(actor, count);
    //                }
    //            }

    //            continuationToken = page.ContinuationToken;
    //        }
    //        while (continuationToken != null);

    //        return actors;
    //    }

    //    public async Task<string> GetChallengeResponseAsync(ActorId actorId, CancellationToken requestAborted)
    //    {
    //        if( await this.StateProvider.ContainsStateAsync(actorId,"cert_" + actorId.GetStringId(),requestAborted))
    //        {
    //            var cert = await this.StateProvider.LoadStateAsync<CertGenerationState>(actorId, "cert_" + actorId.GetStringId(), requestAborted);
    //            while(cert.HttpChallengeInfo == null)
    //            {
    //                await Task.Delay(2000);
    //                cert = await this.StateProvider.LoadStateAsync<CertGenerationState>(actorId, "cert_" + actorId.GetStringId(), requestAborted);

    //            }

    //            return cert.HttpChallengeInfo.KeyAuthString;
    //        }


    //        throw new KeyNotFoundException();
    //    }

    //    public async Task<CertGenerationState[]> GetCerts(CancellationToken cancellationToken)
    //    {

    //        var result = new List<CertGenerationState>();
    //        ContinuationToken continuationToken = null;
    //        do
    //        {

    //            var page = await this.StateProvider.GetActorsAsync(100, continuationToken, cancellationToken);

    //            foreach (var actor in page.Items)
    //            {

    //                var names = await this.StateProvider.EnumerateStateNamesAsync(actor, cancellationToken);

    //                result.AddRange(await Task.WhenAll(names.Where(name => name.StartsWith("cert_"))
    //                    .Select(name => this.StateProvider.LoadStateAsync< CertGenerationState>(actor,name,cancellationToken))));
                    

                    

    //            }

    //            continuationToken = page.ContinuationToken;
    //        }
    //        while (continuationToken != null);
    //        return result.ToArray();
    //    }
    //    public async Task<CertGenerationState> GetCertGenerationInfoAsync(string hostname, SslOptions options, CancellationToken cancellationToken)
    //    {
    //        ContinuationToken continuationToken = null;

    //        do
    //        {

    //            var page = await this.StateProvider.GetActorsAsync(100, continuationToken, cancellationToken);

    //            foreach (var actor in page.Items)
    //            {
    //                if (await this.StateProvider.ContainsStateAsync(actor, $"cert_{hostname}", cancellationToken))
    //                    return await this.StateProvider.LoadStateAsync<CertGenerationState>(actor, $"cert_{hostname}", cancellationToken);

    //            }

    //            continuationToken = page.ContinuationToken;
    //        }
    //        while (continuationToken != null);

    //        return null;
    //    }


    //}
}
