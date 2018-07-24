using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using Newtonsoft.Json;
using System;
using System.Security.Claims;

[assembly: FabricTransportServiceRemotingProvider( RemotingClientVersion = RemotingClientVersion.V2_1, RemotingListenerVersion = RemotingListenerVersion.V2_1)]


namespace SInnovations.ServiceFabric.ResourceProvider
{
    public class ClaimConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return typeof(Claim) == objectType;
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            var source = serializer.Deserialize<ClaimLite>(reader);
            var target = new Claim(source.Type, source.Value, source.ValueType);
            return target;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var source = (Claim)value;

            var target = new ClaimLite
            {
                Type = source.Type,
                Value = source.Value,
                ValueType = source.ValueType
            };

            serializer.Serialize(writer, target);
        }
    }

}
