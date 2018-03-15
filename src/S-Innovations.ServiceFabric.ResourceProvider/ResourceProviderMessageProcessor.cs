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

 
namespace SInnovations.ServiceFabric.ResourceProvider
{
    public class ResourceProviderMessageProcessor : IHostedService
    {
        private readonly ILoggerFactory loggerFactory;
        private readonly MessageProcessorOptions options;
        private readonly IServiceScopeFactory serviceScopeFactory;
        private readonly ILogger logger;
        private IMessageProcessorClient _processor;

        public ResourceProviderMessageProcessor(ILoggerFactory loggerFactory, MessageProcessorOptions options, IServiceScopeFactory serviceScopeFactory)
        {
            this.loggerFactory = loggerFactory;
            this.options = options;
            this.serviceScopeFactory = serviceScopeFactory;
            this.logger = loggerFactory.CreateLogger<ResourceProviderMessageProcessor>();
        }
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            _processor = CreateProcessor();
            await _processor.StartProcessorAsync();
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
