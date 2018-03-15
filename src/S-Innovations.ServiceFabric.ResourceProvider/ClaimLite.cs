using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;

 

namespace SInnovations.ServiceFabric.ResourceProvider
{
    public class ClaimLite
    {
        public string Type { get; set; }
        public string Value { get; set; }
        public string ValueType { get; set; }
    }

}
