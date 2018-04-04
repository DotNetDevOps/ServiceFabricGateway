using SInnovations.ServiceFabric.Gateway.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Model
{

    [DataContract]
    [KnownType(typeof(string[]))]
    public class GatewayOptions : IExtensibleDataObject
    {
        public string Key { get; set; }
        public string ReverseProxyLocation { get; set; }
        public string ServerName { get; set; }
        public SslOptions Ssl { get; set; } = new SslOptions();
        public ProxyPassCacheOptions CacheOptions { get; set; } = new ProxyPassCacheOptions();

        public Dictionary<string, object> Properties { get; set; } = new Dictionary<string, object>();

        private ExtensionDataObject theData;

        public virtual ExtensionDataObject ExtensionData
        {
            get { return theData; }
            set { theData = value; }
        }

    }
}
