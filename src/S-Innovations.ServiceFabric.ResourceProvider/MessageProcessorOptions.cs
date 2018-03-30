﻿using Microsoft.Extensions.Options;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;

 
namespace SInnovations.ServiceFabric.ResourceProvider
{
    public class MessageProcessorOptions
    {
       
 
        public int ConcurrentMessagesProcesses { get; set; }
        public string QueuePath { get; set; }
      }

}
