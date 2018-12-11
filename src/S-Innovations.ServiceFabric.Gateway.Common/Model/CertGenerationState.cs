using SInnovations.ServiceFabric.Gateway.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.Gateway.Common.Model
{
    [DataContract]
    public class CertHttpChallengeInfo : IExtensibleDataObject
    {
        [DataMember]
        public string KeyAuthString { get; set; }

        [DataMember]
        public string Location { get; private set; }
        [DataMember]
        public string Token { get; set; }

        public CertHttpChallengeInfo SetLocation(string location)
        {
            Location = location;
            return Clone();
          
        }
        private ExtensionDataObject theData;

        public virtual ExtensionDataObject ExtensionData
        {
            get { return theData; }
            set { theData = value; }
        }

        
        public CertHttpChallengeInfo Clone()
        {
            return new CertHttpChallengeInfo { Location = Location, Token = Token, KeyAuthString = KeyAuthString, ExtensionData=ExtensionData};
        }

    }
    [DataContract]
    public class CertGenerationState: IExtensibleDataObject
    {
        public const string CERTGENERATION_VERSION = "1.0";

        private ExtensionDataObject theData;

        public virtual ExtensionDataObject ExtensionData
        {
            get { return theData; }
            set { theData = value; }
        }


        public CertGenerationState()
        {
            RunAt = DateTimeOffset.UtcNow;
            Version = CERTGENERATION_VERSION;
        }
        public CertGenerationState(bool completed) : this()
        {
            Completed = completed;

        }

        [DataMember]
        public bool Completed { get; private set; }

        [DataMember]
        public int Counter { get; private set; } = 0;

       
        [DataMember]
        public string HostName { get; set; }
        [DataMember]
        public SslOptions SslOptions { get; set; }
        [DataMember]
        public DateTimeOffset? RunAt { get; private set; }
        [DataMember]
        public CertHttpChallengeInfo HttpChallengeInfo { get; private set; }
        [DataMember]
        public string OrderLocation { get; private set; }

        [DataMember]
        public string Version { get; private set; }

        public CertGenerationState Refresh(bool force, string hostname, SslOptions options)
        {
            Completed = !force && Completed;
            hostname = HostName;
            SslOptions = options;
            return Clone();
        }

        public CertGenerationState Complete()
        {
            this.Completed = true;
            this.RunAt = DateTimeOffset.UtcNow;
            this.Version = CERTGENERATION_VERSION;
            return Clone();

        }

        public CertGenerationState SetCertHttpChallengeLocation(string location)
        {
            return SetCertHttpChallengeInfo(HttpChallengeInfo.SetLocation(location));
            
        }
        public CertGenerationState SetCertHttpChallengeInfo(CertHttpChallengeInfo certHttpChallengeInfo)
        {
            HttpChallengeInfo = certHttpChallengeInfo;
            return Clone();
        }

        public CertGenerationState Increment()
        {
            Counter += 1;
            return Clone();
           
        }

        public CertGenerationState SetOrderLocation(string absoluteUri)
        {
            this.OrderLocation = absoluteUri;
            return Clone();
            
             
        }

        public CertGenerationState Clone()
        {
            return new CertGenerationState
            {
                Completed = Completed,
                HostName = HostName,
                SslOptions = new SslOptions { Enabled = SslOptions.Enabled, SignerEmail = SslOptions.SignerEmail, UseHttp01Challenge = SslOptions.UseHttp01Challenge },
                RunAt = RunAt,
                HttpChallengeInfo = HttpChallengeInfo?.Clone(),
                OrderLocation = OrderLocation, Counter=Counter, ExtensionData = ExtensionData,
                Version = Version
            };
        }

        public CertGenerationState RestartOrder()
        {
            var clone = Increment();
            clone.HttpChallengeInfo = null;
            return clone;
        }
    }
}
