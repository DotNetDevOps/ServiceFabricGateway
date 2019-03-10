using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using SInnovations.ServiceFabric.Gateway.Common.Services;
using SInnovations.ServiceFabric.Storage.Extensions;

namespace SInnovations.ServiceFabric.Storage.Clients
{
    public class ArmClient
    {
        
        private AsyncExpiringLazy<AuthenticationHeaderValue> _token;
        protected HttpClient Client { get; set; }

        public ArmClient(HttpClient client, IAzureADTokenService azureAD)
        {
            Client = client;
            _token = new AsyncExpiringLazy<AuthenticationHeaderValue>(async old =>
              {
                 
                 
                  return new ExpirationMetadata<AuthenticationHeaderValue>
                  {
                      Result = new AuthenticationHeaderValue("Bearer", await azureAD.GetTokenAsync()),
                      ValidUntil = DateTimeOffset.UtcNow.AddMinutes(10)
                  };
              });
        }
        public ArmClient( AuthenticationHeaderValue authorization)
        {
            Client = new HttpClient();
            _token = new AsyncExpiringLazy<AuthenticationHeaderValue>((old) => Task.FromResult(new ExpirationMetadata<AuthenticationHeaderValue> {  Result = authorization}));
           
        }

        public ArmClient(string accessToken) : this(new AuthenticationHeaderValue("Bearer", accessToken))
        {

        }

        public async Task<T> ListKeysAsync<T>(string resourceId, string apiVersion)
        {
         
            var resourceUrl = $"https://management.azure.com/{resourceId.Trim('/')}/listkeys?api-version={apiVersion}";
            var msg = new HttpRequestMessage(HttpMethod.Post, resourceUrl);
            msg.Content = new StringContent(string.Empty);
            msg.Headers.Authorization = await _token;

            return await Client.SendAsync(msg).As<T>();

          
        }

        public Task<T> PatchAsync<T>(string resourceId, T value, string apiVersion)
        {
            var resourceUrl = $"https://management.azure.com/{resourceId.Trim('/')}?api-version={apiVersion}";
            var request = new HttpRequestMessage(new HttpMethod("PATCH"), resourceUrl);
            var valuestr = JsonConvert.SerializeObject(value);
            request.Content = new StringContent(valuestr, Encoding.UTF8, "application/json");

            return Client.SendAsync(request)
                .As<T>();
        }

        public Task<T> GetAsync<T>(string resourceId, string apiVersion)
        {
            var resourceUrl = $"https://management.azure.com/{resourceId.Trim('/')}?api-version={apiVersion}";
            return Client.GetAsync(resourceUrl).As<T>();
        }
    }
}
