using System;
using System.Collections.Generic;
using System.Fabric;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.ServiceFabric.Services.Communication.Client;

namespace SInnovations.ServiceFabric.Gateway.Communication
{

    public class HttpCommunicationClient : ICommunicationClient
    {  
        public HttpClient HttpClient { get; set; }
        //public HttpCommunicationClient()
        //    : base(new HttpClientHandler() { AllowAutoRedirect = false, UseCookies = false })
        //{
        //}

        //public HttpCommunicationClient(HttpMessageHandler handler)
        //    : base(handler)
        //{
        //}

        //public HttpCommunicationClient(HttpMessageHandler handler, bool disposeHandler)
        //    : base(handler, disposeHandler)
        //{       
        //}
        public HttpCommunicationClient(HttpClient client)
        {
            HttpClient = client;
        }

        #region ICommunicationClient

        public string ListenerName { get; set; }

        public ResolvedServiceEndpoint Endpoint { get; set; }

        public ResolvedServicePartition ResolvedServicePartition { get; set; }

        #endregion ICommunicationClient
    }
}
