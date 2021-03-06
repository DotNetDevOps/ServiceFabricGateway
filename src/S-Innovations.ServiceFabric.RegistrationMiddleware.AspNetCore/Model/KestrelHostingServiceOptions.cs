﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Model
{
    public class KestrelHostingServiceOptions
    {
        public string ServiceEndpointName { get; set; }

        public GatewayOptions GatewayOptions { get; set; } = new GatewayOptions();

        public ICollection<GatewayOptions> AdditionalGateways { get; set; } = new List<GatewayOptions>();
        public string GatewayApplicationName { get;  set; }
    }
}
