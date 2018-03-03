using SInnovations.ServiceFabric.Gateway.Model;
using System;
using System.Collections.Generic;
using System.Fabric;
using System.Linq;

namespace SInnovations.ServiceFabric.GatewayService.Services
{
    public static class NginxEx
    {
        public static IDictionary<string, List<GatewayServiceRegistrationData>> GroupByServerName(this List<GatewayServiceRegistrationData> proxies)
        {

            var servers = proxies.SelectMany(g =>
                        (g.ServerName ?? FabricRuntime.GetNodeContext().IPAddressOrFQDN)
                        .Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(k => new { sslKey = k + g.Ssl, key = k, value = g }))
                    .GroupBy(k => k.sslKey).ToDictionary(k => k.Key, k => new { hostname = k.First().key, locations = k.Select(v => v.value).ToList() });



            var singles = servers.Where(k => k.Value.locations.Count > 1)
                .ToDictionary(k => k.Value.hostname, v => v.Value.locations);


            foreach (var combine in servers.Where(k => k.Value.locations.Count == 1).GroupBy(k => k.Value.locations.First()))
            {
                singles.Add(string.Join(" ", combine.Select(k => k.Value.hostname)), new List<GatewayServiceRegistrationData> { combine.Key });
            }

            foreach (var test in singles.ToArray())
            {
                if (test.Value.Any(k => k.Ssl.Enabled) && test.Key.Contains(' '))
                {
                    foreach (var hostname in test.Key.Split(' '))
                    {
                        if (singles.ContainsKey(hostname))
                        {
                            singles[hostname].AddRange(test.Value);
                        }
                        else
                        {
                            singles.Add(hostname, test.Value);
                        }
                    }

                    singles.Remove(test.Key);
                }
            }


            return singles;
        }
    }
}
