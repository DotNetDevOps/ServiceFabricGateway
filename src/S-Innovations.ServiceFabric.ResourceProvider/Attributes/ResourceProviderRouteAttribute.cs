using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.ResourceProvider.Attributes
{
    public class ResourceProviderRouteAttribute : RouteAttribute
    {
        public const string ResourceGroupsRoutingParameter = "resourcegroups";
        public const string SubscriptionsRoutingParameter = "subscriptions";
        public const string ProviderRoutingParameter = "providers";

        public ResourceProviderRouteAttribute(string provider, string route, bool withSubscriptionRouting = true, bool withResourceGroupRouting = true, string subscriptionsRoutingParameter = SubscriptionsRoutingParameter, string resourceGroupsRoutingParameter = ResourceGroupsRoutingParameter, string providerRoutingParameter = ProviderRoutingParameter)
            : base($"{(withSubscriptionRouting ? $"{subscriptionsRoutingParameter}/{{subscriptionId}}" : "")}{(withResourceGroupRouting ? $"/{resourceGroupsRoutingParameter}/{{resourceGroupName}}" : "")}/{providerRoutingParameter}/{provider}/{route}".Trim('/'))
        {

        }


    }
    public class ProviderRouteAttribute : ResourceProviderRouteAttribute
    {
        public ProviderRouteAttribute(string provider, string route) : base(provider, route, false, false)
        {
        }


    }
    public class ProviderAttribute : ProviderRouteAttribute
    {
        public ProviderAttribute(string provider) : base(provider, "")
        {
        }
    }
}
