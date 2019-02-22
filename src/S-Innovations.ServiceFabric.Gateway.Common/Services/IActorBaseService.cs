using Microsoft.ServiceFabric.Actors;
using Microsoft.ServiceFabric.Actors.Client;
using Microsoft.ServiceFabric.Actors.Runtime;
using Microsoft.ServiceFabric.Services.Remoting;
using System;
using System.Fabric;
using System.Runtime.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric
{
    public interface IActorBaseService : IService, IActorService
    {
        Task<bool> ActorExists(ActorId actorId, CancellationToken cancellationToken);
        Task ActorUpdatedAsync(ActorId actorid, DateTimeOffset time, bool initialzieOnMissing, CancellationToken cancellationToken);
        Task DeactivateAsync(ActorId id);
    }


    [DataContract]
    public class DocumentWrapper
    {
        [DataMember]
        public Object Document { get; set; }
    }

    public interface IDocumentActorBaseService : IActorBaseService, IService, IActorService
    {
        Task SaveDocumentAsync(ActorId actorId, DocumentWrapper document, CancellationToken cancellationToken);
        Task<object> GetDocumentAsync(ActorId actorId, CancellationToken requestAborted);
    }

    public static class Constants
    {
        public const string ActivatedStateName = "Activated";
        public const string LastUpdatedStateName = "LastUpdated";
    }
    public interface IDocumentActor : IActor
    {
        Task InitializeAsync();
        Task DocumentUpdatedAsync();
    }
    public static class TaskHelper
    {
        public static void FireAndForget(this Task task)
        {
            Task.Run(async () => await task).ConfigureAwait(false);
        }
    }
    public class ActorBaseService<TDocument> : ActorService, IDocumentActorBaseService
    {

        public ActorBaseService(
            StatefulServiceContext context,
            ActorTypeInformation actorTypeInfo,
            Func<ActorService, ActorId, ActorBase> actorFactory,
            Func<ActorBase, IActorStateProvider, IActorStateManager> stateManagerFactory = null,
            IActorStateProvider stateProvider = null,
            ActorServiceSettings settings = null) : base(context, actorTypeInfo, actorFactory, stateManagerFactory, stateProvider, settings)
        {

        }
        public async Task<bool> ActorExists(ActorId actorId, CancellationToken cancellationToken)
        {
            try
            {
                return await StateProvider.ContainsStateAsync(actorId, Constants.ActivatedStateName, cancellationToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                throw;
            }
        }

        public async Task DeactivateAsync(ActorId actorId)
        {
            try
            {
                await StateProvider.SaveStateAsync(actorId, new[] { new ActorStateChange(Constants.ActivatedStateName, typeof(bool), false, StateChangeKind.Update) });
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                throw;
            }
        }




        public async Task ActorUpdatedAsync(ActorId actorid, DateTimeOffset time, bool initializeOnMissing, CancellationToken cancellationToken)
        {
            try
            {
                if (await StateProvider.ContainsStateAsync(actorid, Constants.ActivatedStateName, cancellationToken))
                {
                    if (await StateProvider.ContainsStateAsync(actorid, Constants.LastUpdatedStateName, cancellationToken))
                    {
                        var old = await StateProvider.LoadStateAsync<DateTimeOffset>(actorid, Constants.LastUpdatedStateName, cancellationToken);

                        if (time > old)
                        {
                            await StateProvider.SaveStateAsync(actorid,
                                 new ActorStateChange[] {
                            new ActorStateChange(Constants.LastUpdatedStateName, typeof(DateTimeOffset), time, StateChangeKind.Update)
                             }, cancellationToken);
                        }
                        else
                        {
                            return;
                        }
                    }
                    else
                    {

                        await StateProvider.SaveStateAsync(actorid,
                             new ActorStateChange[] {
                         new ActorStateChange(Constants.LastUpdatedStateName, typeof(DateTimeOffset), time, StateChangeKind.Add)
                         }, cancellationToken);


                    }

                    if (!await StateProvider.LoadStateAsync<bool>(actorid, Constants.ActivatedStateName, cancellationToken))
                    {
                        ActorProxy.Create<IDocumentActor>(actorid, this.Context.ServiceName).DocumentUpdatedAsync().FireAndForget();
                    }
                }
                else if (initializeOnMissing)
                {
                    ActorProxy.Create<IDocumentActor>(actorid, this.Context.ServiceName).InitializeAsync().FireAndForget();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                throw;
            }
        }

        public async Task SaveDocumentAsync(ActorId actorId, DocumentWrapper document, CancellationToken cancellationToken)
        {


            await StateProvider.SaveStateAsync(actorId,
                    new ActorStateChange[] {
                         new ActorStateChange("Document", typeof(TDocument), document.Document,
                         await StateProvider.ContainsStateAsync(actorId, "Document", cancellationToken) ? StateChangeKind.Update: StateChangeKind.Add)
                }, cancellationToken);

            await ActorUpdatedAsync(actorId, DateTimeOffset.UtcNow, true, cancellationToken);

        }

        public async Task<object> GetDocumentAsync(ActorId actorId, CancellationToken requestAborted)
        {
            if (await StateProvider.ContainsStateAsync(actorId, "Document", requestAborted))
                return await StateProvider.LoadStateAsync<TDocument>(actorId, "Document", requestAborted);

            return null;
        }
    }

}
