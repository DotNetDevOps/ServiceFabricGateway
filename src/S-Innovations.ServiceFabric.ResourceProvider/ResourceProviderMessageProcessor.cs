using Microsoft.Extensions.Logging;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using SInnovations.Azure.MessageProcessor.Core;
using SInnovations.Azure.MessageProcessor.ServiceBus;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using System.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Azure.ServiceBus;
using SInnovations.Azure.MessageProcessor.Core.Notifications;
using System.Diagnostics;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ServiceFabric.Services.Runtime;
using Microsoft.Extensions.Configuration;
using System.Fabric;
using System.Collections.Generic;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Remoting.Runtime;

namespace SInnovations.ServiceFabric.ResourceProvider
{
    public interface IResourceProviderService : IService
    {

    }
    //public interface IFabicHostedServiceFactory<T> where T : IHostedService
    //{
    //    Task<T> CreateHostedServiceAsync();
    //}
    public class ResourceProviderAttribute : Attribute
    {
        public string ProviderNamespace { get; protected set; }
        

        public ResourceProviderAttribute(string providerNamespace)
        {
            ProviderNamespace = providerNamespace;
        }
    }

    public class FabicHostedService<T> : StatelessService where T:IHostedService
    {
        private readonly T hostedService;

        public FabicHostedService(StatelessServiceContext serviceContext,T hostedService ) : base(serviceContext)
        {
            this.hostedService = hostedService;
        }

       
        protected override async Task RunAsync(CancellationToken cancellationToken)
        {
            await hostedService.StartAsync(cancellationToken);

            await base.RunAsync(cancellationToken);
        }
        
        protected override async Task OnCloseAsync(CancellationToken cancellationToken)
        {
            await hostedService.StopAsync(cancellationToken);

            await base.OnCloseAsync(cancellationToken);
        }
    }
    public class ResourceProviderService : StatelessService, IResourceProviderService
    {
        private readonly IConfigurationRoot configuration;

        public ResourceProviderService(StatelessServiceContext serviceContext, IConfigurationRoot configuration) : base(serviceContext)
        {
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }



        protected override IEnumerable<ServiceInstanceListener> CreateServiceInstanceListeners()
        {
            return this.CreateServiceRemotingInstanceListeners();
        }


       
    }

    //public class ResourceProviderMessageProcessorFactory : IFabicHostedServiceFactory<ResourceProviderMessageProcessor>
    //{
    //    private readonly ILoggerFactory loggerFactory;
    //    private readonly MessageProcessorOptions options;
    //    private readonly IServiceScopeFactory serviceScopeFactory;

    //    public ResourceProviderMessageProcessorFactory(ILoggerFactory loggerFactory, MessageProcessorOptions options, IServiceScopeFactory serviceScopeFactory)
    //    {
    //        this.loggerFactory = loggerFactory;
    //        this.options = options;
    //        this.serviceScopeFactory = serviceScopeFactory;
    //    }
    //    public Task<ResourceProviderMessageProcessor> CreateHostedServiceAsync()
    //    {
    //        return Task.FromResult(new ResourceProviderMessageProcessor(loggerFactory,options,serviceScopeFactory));    
    //    }
    //}

    public class ResourceProviderMessageProcessorHostedService : IHostedService
    {
        private readonly ILoggerFactory loggerFactory;
        private readonly MessageProcessorOptions options;
        private readonly IKeyVaultService keyVaultService;
        private readonly IServiceScopeFactory serviceScopeFactory;
        private readonly ILogger logger;
        private IMessageProcessorClient _processor;

        public ResourceProviderMessageProcessorHostedService(
             IServiceScopeFactory serviceScopeFactory,
            ILoggerFactory loggerFactory,
            MessageProcessorOptions options,
            IKeyVaultService keyVaultService 
           )
        {
            this.loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
            this.options = options ?? throw new ArgumentNullException(nameof(options));
            this.keyVaultService = keyVaultService ?? throw new ArgumentNullException(nameof(keyVaultService));
            this.serviceScopeFactory = serviceScopeFactory ?? throw new ArgumentNullException(nameof(serviceScopeFactory));
            this.logger = loggerFactory.CreateLogger<ResourceProviderMessageProcessorHostedService>();
        }
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            options.ListenerConnectionString = options.ListenerConnectionString ??
                await keyVaultService.GetSecretAsync(options.ListenerConnectionStringKey);

            if (string.IsNullOrEmpty(options.ListenerConnectionString))
                throw new Exception("Missing connection string");

            _processor = CreateProcessor();
            try
            {
                await _processor.StartProcessorAsync();
            }catch(Exception ex)
            {
                logger.LogError(ex, "Failed To start hosted service");
                logger.LogInformation("Failed To start hosted service: {exception}", ex.ToString());
            }
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            await _processor.StopProcessorAsync();
        }

        private IMessageProcessorClient CreateProcessor()
        {


            return new MessageProcessorClient<Message>(
                loggerFactory.CreateLogger<MessageProcessorClient<Message>>(),
                 new MessageProcessorClientOptions<Message>
                 {
                     Provider = new ServiceBusMessageProcessorProvider(loggerFactory,
                     new ServiceBusMessageProcessorProviderOptions
                     {
                         ConnectionString = options.ListenerConnectionString,
                         MaxConcurrentProcesses = options.ConcurrentMessagesProcesses, //High IO depended message processing for relocation of data and reordering.
                         MaxMessageRetries = 3,
                         QueueDescription = new QueueDescription(options.QueuePath),

                     }),
                     HandlerTimeOut = TimeSpan.FromMinutes(60),
                     ResolverProvider = () => new HandlerResolver(serviceScopeFactory.CreateScope()), // return new UnityHandlerResolver(container); },
                     IdleTimeCheckInterval = TimeSpan.FromMinutes(5),
                     Notifications = new DefaultNotifications
                     {
                         OnIdleNotification = (m) =>
                         {

                             logger.LogInformation("Idling for {idleMinutes} mins and {idleSecs} secs", m.IdleTime.Minutes, m.IdleTime.Seconds);
                             return Task.FromResult(0);

                         },
                         OnMessageStarted = (notice) =>
                         {

                             // CallContext.LogicalSetData(ItemCorrelationTelemetryInitializer.DEFAULT_CORRELATION_SLOT, notice.Message.MessageId);
                             Trace.CorrelationManager.ActivityId = Guid.NewGuid();
                             return Task.FromResult(0);
                         },
                         OnMovingMessageToDeadLetter = (notice) =>
                         {
                             //   Trace.TraceWarning("MovingMessageToDeadLetter: {0}", notice.Message.GetType().Name); 
                             TelemetryClient rtClient = (TelemetryClient)notice.Resolver.GetHandler(typeof(TelemetryClient));
                             var t = new EventTelemetry("MovingMessageToDeadLetter")
                             {
                                 Timestamp = DateTimeOffset.Now,
                             };
                             t.Properties.Add("MessageId", notice.Message.MessageId);
                             t.Properties.Add("MessageType", notice.Message.GetType().Name);
                             rtClient.TrackEvent(t);

                             return Task.FromResult(0);
                         },
                         OnMessageCompleted = async (notice) =>
                         {
                             // await notice.TrackMessageCompletedAsync();

                         }
                     }

                 });
        }
    }

}
