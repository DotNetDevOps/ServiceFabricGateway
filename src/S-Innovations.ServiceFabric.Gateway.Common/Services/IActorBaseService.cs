﻿using Microsoft.Extensions.Logging;
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
       // Task SaveDocumentAsync(ActorId actorId, DocumentWrapper document, CancellationToken cancellationToken);
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
        Task SetLastUpdatedAsync(DateTimeOffset time);
    }
    public static class TaskHelper
    {
        public static void FireAndForget(this Task task)
        {
            Task.Run(async () => await task).ConfigureAwait(false);
        }
    }
    public abstract class DocumentActor<T> : Actor
    {
        public const string DocumentStateKey = "Document";
        protected readonly ILogger _logger;

        protected DocumentActor(ActorService actorService, ActorId actorId, ILogger logger) : base(actorService, actorId)
        {
            this._logger = logger;
        }
        public Task<T> DocumentAsync => StateManager.GetStateAsync<T>(DocumentStateKey);
        public Task<bool> HasDocumentAsync => StateManager.ContainsStateAsync(DocumentStateKey);
        public Task SetDocumentAsync(T document) => StateManager.SetStateAsync(DocumentStateKey, document).ContinueWith(c => SetLastUpdatedAsync(DateTimeOffset.UtcNow));

        public virtual  Task DocumentUpdatedAsync()
        {

         //   await  this.SaveStateAsync();
         //   await this.StateManager.ClearCacheAsync();
            return Task.CompletedTask;
        }

        public virtual Task InitializeAsync()
        {
            return Task.CompletedTask;
        }

        private IActorTimer _updateTimer;
       // protected DateTimeOffset? LastUpdated { get; set; }

        public async Task  SetLastUpdatedAsync(DateTimeOffset time) { await StateManager.SetStateAsync(Constants.LastUpdatedStateName, time);   }


        protected DateTimeOffset _lastChecked = DateTimeOffset.MinValue;
        protected Task _longRunningOnUpdated = null;
        protected int attempts = 0;


        protected override async Task OnActivateAsync()
        {
            await StateManager.SetStateAsync(Constants.ActivatedStateName, true);
            await StateManager.SetStateAsync(Constants.LastUpdatedStateName, DateTimeOffset.UtcNow);


            _updateTimer = RegisterTimer(
             OnUpdateCheckAsync,                     // Callback method
             null,                           // Parameter to pass to the callback method
             TimeSpan.FromMinutes(0),  // Amount of time to delay before the callback is invoked
             TimeSpan.FromSeconds(10)); // Time interval between invocations of the callback method

            _logger.LogDebug("Activated {ActorId} on {ActorService}", this.Id, this.ServiceUri);
        }

        private DateTimeOffset _startedUpdated = DateTimeOffset.UtcNow;
        private DateTimeOffset _endUpdated = DateTimeOffset.UtcNow;


        private async Task OnUpdateCheckAsync(object arg)
        {

            var updatedAt =  await StateManager.GetStateAsync<DateTimeOffset>(Constants.LastUpdatedStateName);

            if (_longRunningOnUpdated == null)
            {

                if (updatedAt > _lastChecked)
                {


                    _logger.LogDebug("Running OnUpdated for {actorId} {attempt} for {updatedAt}", Id.ToString(), ++attempts, updatedAt);


                    _longRunningOnUpdated = Task.Run(async () => { try { _startedUpdated = DateTimeOffset.UtcNow; await OnUpdatedAsync(); } finally { _endUpdated = DateTimeOffset.UtcNow; } _lastChecked = updatedAt; attempts = 0; });


                }
            }
            else if (_longRunningOnUpdated.Status == TaskStatus.RanToCompletion)
            {
                _logger.LogDebug("OnUpdated for {actorId} ran to completion for {attempt} in {time}", Id.ToString(), attempts, _endUpdated.Subtract(_startedUpdated));

                _longRunningOnUpdated = null;
            }
            else if (_longRunningOnUpdated.Status == TaskStatus.Faulted)
            {
                _logger.LogDebug(_longRunningOnUpdated.Exception, "OnUpdated for {actorId} faulted in {time} and will reset", Id.ToString(), _endUpdated.Subtract(_startedUpdated));
                _longRunningOnUpdated = null;
                if (attempts > 2)
                {
                    _logger.LogWarning(_longRunningOnUpdated.Exception, "OnUpdated for {actorId} faulted {attempts} in {time} and will skip resetting",Id.ToString(),attempts, _endUpdated.Subtract(_startedUpdated));
                    _lastChecked = updatedAt;
                }
            }
            else if (_longRunningOnUpdated.Status == TaskStatus.Canceled)
            {
                _logger.LogDebug("OnUpdated for {actorId} was canceled in {time}", Id.ToString(), _endUpdated.Subtract(_startedUpdated));
                _longRunningOnUpdated = null;
            }
            else
            {
                //Keep the actor alive
                await ActorProxy.Create<IDocumentActor>(this.Id, this.ServiceUri).DocumentUpdatedAsync();
            }

        }
        protected virtual  Task OnUpdatedAsync()
        {
            //await this.StateManager.SaveStateAsync();
            //await this.StateManager.ClearCacheAsync();
              return Task.CompletedTask;
        }
        protected override async Task OnDeactivateAsync()
        {
            if (_updateTimer != null)
            {
                UnregisterTimer(_updateTimer);
            }
            var service = this.ActorService as ActorBaseService<T>;
            await service.DeactivateAsync(Id); ;
           // await ActorServiceProxy.Create<IActorBaseService>(ServiceUri, Id).DeactivateAsync(Id);

            await base.OnDeactivateAsync();

            _logger.LogDebug("Deactivated {ActorId} on {ActorService}", this.Id, this.ServiceUri);
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
                            await ActorProxy.Create<IDocumentActor>(actorid, this.Context.ServiceName).SetLastUpdatedAsync(time);
                            //await StateProvider.SaveStateAsync(actorid,
                            //     new ActorStateChange[] {
                            //new ActorStateChange(Constants.LastUpdatedStateName, typeof(DateTimeOffset), time, StateChangeKind.Update)
                            // }, cancellationToken);
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

                    //if (!await StateProvider.LoadStateAsync<bool>(actorid, Constants.ActivatedStateName, cancellationToken))
                    //{
                    //    ActorProxy.Create<IDocumentActor>(actorid, this.Context.ServiceName).DocumentUpdatedAsync().FireAndForget();
                    //}
                }
                else if (initializeOnMissing)
                {
                    ActorProxy.Create<IDocumentActor>(actorid, this.Context.ServiceName).InitializeAsync().FireAndForget();
                }

                ActorProxy.Create<IDocumentActor>(actorid, this.Context.ServiceName).DocumentUpdatedAsync().FireAndForget();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                throw;
            }
        }

        public async Task SaveDocumentAsync(ActorId actorId, TDocument document, CancellationToken cancellationToken)
        {

             

            await StateProvider.SaveStateAsync(actorId,
                    new ActorStateChange[] {
                         new ActorStateChange("Document", typeof(TDocument), document,
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
