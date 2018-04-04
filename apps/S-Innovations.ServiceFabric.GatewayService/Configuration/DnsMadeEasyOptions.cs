using Microsoft.Extensions.Options;
using SInnovations.DnsMadeEasy;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{
    public class DnsMadeEasyOptions : DnsMadeEasyClientCredetials
    {
        public DnsMadeEasyOptions(IOptions<KeyVaultOptions> keyvault)
        {
            var parts = keyvault.Value.DnsMadeEasyCredentials.Split(':');
            this.ApiKey = parts[0];
            this.ApiSecret = parts[1];
        }
    }










}
