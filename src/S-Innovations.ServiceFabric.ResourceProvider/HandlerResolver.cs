using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using SInnovations.Azure.MessageProcessor.Core;
using System;
using Microsoft.Extensions.DependencyInjection;



namespace SInnovations.ServiceFabric.ResourceProvider
{
    public class HandlerResolver : IMessageHandlerResolver
    {
        private readonly IServiceScope scope;
        /// <summary>
        /// Instianciate a new Dependency Resolver given a scope.
        /// </summary>
        public HandlerResolver(IServiceScope scope)
        {
            this.scope = scope;
        }

        public object GetHandler(Type constructed)
        {
            return this.scope.ServiceProvider.GetService(constructed);
        }

        public void Dispose()
        {
            this.scope.Dispose();
        }
    }

}
