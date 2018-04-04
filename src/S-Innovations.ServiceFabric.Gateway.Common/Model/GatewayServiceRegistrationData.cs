using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.Gateway.Model
{
    [DataContract]
    public class ProxyPassCacheOptions
    {
        [DataMember]
        public bool Enabled { get; set; }
    }
    [DataContract]
    [KnownType(typeof(string[]))]
    public class GatewayServiceRegistrationData : IExtensibleDataObject
    {
       // public string ProxyName => Key.Substring(0, Key.Length - IPAddressOrFQDN.Length - 1);

        [DataMember]
        public string ReverseProxyLocation { get; set; }
        [DataMember]
        public string BackendPath { get; set; }
        [DataMember]
        public string IPAddressOrFQDN { get; set; }

        [DataMember]
        public string ServerName { get; set; }

        [DataMember]
        public string Key { get; set; }

        [DataMember]
        public SslOptions Ssl { get; set; } = new SslOptions();

        [DataMember]
        public Uri ServiceName { get; set; }

        [DataMember]
        public string ServiceVersion { get; set; }

        [DataMember]
        public ProxyPassCacheOptions CacheOptions { get; set; } = new ProxyPassCacheOptions();

        [DataMember]
        public Dictionary<string, object> Properties { get; set; } = new Dictionary<string, object>();

        [DataMember]
        public DateTimeOffset Time { get; private set; } = DateTimeOffset.UtcNow;

        [DataMember]
        public bool Ready { get; set; } = true;

        private ExtensionDataObject theData;

        public virtual ExtensionDataObject ExtensionData
        {
            get { return theData; }
            set { theData = value; }
        }

        public GatewayServiceRegistrationData MarkAsDead()
        {
            return new GatewayServiceRegistrationData
            {
                ReverseProxyLocation = ReverseProxyLocation,
                BackendPath = BackendPath,
                CacheOptions = CacheOptions,
                ExtensionData = ExtensionData,
                IPAddressOrFQDN = IPAddressOrFQDN,
                Key = Key,
                Properties = Properties,
                ServerName = ServerName,
                ServiceName = ServiceName,
                ServiceVersion = ServiceVersion,
                Ssl = Ssl,
                Time = Time,
                Ready = false
            };
        }

        public GatewayServiceRegistrationData MarkAsReady()
        {
            return new GatewayServiceRegistrationData
            {
                ReverseProxyLocation = ReverseProxyLocation,
                BackendPath = BackendPath,
                CacheOptions = CacheOptions,
                ExtensionData = ExtensionData,
                IPAddressOrFQDN = IPAddressOrFQDN,
                Key = Key,
                Properties = Properties,
                ServerName = ServerName,
                ServiceName = ServiceName,
                ServiceVersion = ServiceVersion,
                Ssl = Ssl,
                Time = DateTimeOffset.UtcNow,
                Ready = true
            };
        }
    }
}
