using System;
using System.Collections.Generic;
using System.Fabric;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json.Linq;

namespace SInnovations.ServiceFabric.Storage.Configuration
{
    //public interface IAzureAd
    //{
    //    Task<string> GetAccessToken();
    //    Task<string> GetTokenFromClientSecret(string authority, string resource);
    //}
    //public class MSIAzureAdConfiguration : IAzureAd
    //{
    //    public Task<string> GetAccessToken()
    //    {
         
    //    }

    //    public Task<string> GetTokenFromClientSecret(string authority, string resource)
    //    {
    //        throw new NotImplementedException();
    //    }
    //}
    public class AzureADConfiguration 
    {
        private readonly TokenCache _cache;
        private readonly ConfigurationPackage _config;
        private readonly ILogger logger;
        // private readonly 
        public AzureADConfiguration(ConfigurationPackage configurationPackage, TokenCache cache, ILoggerFactory loggerFactory)
        {
            logger = loggerFactory?.CreateLogger<AzureADConfiguration>() ?? throw new ArgumentNullException(nameof(loggerFactory));

            _cache = cache;
            _config = configurationPackage;



        }


        static ClientCredential ParseSecureString(SecureString value)
        {
            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
             //   var secureStringPassword = new SecureString();

                var chars = new char[1];
                var clientId = new StringBuilder();
                var secret = new StringBuilder();
                var clientIdDone = false;
                for (int i = 0; i < value.Length; i++)
                {
                    short unicodeChar = Marshal.ReadInt16(valuePtr, i * 2);
                    var c = Convert.ToChar(unicodeChar);


                    if (!clientIdDone)
                    {
                        if (c != ':')
                        {
                            clientId.Append(c);
                        }
                        else
                        {
                            clientIdDone = true;
                        }
                    }
                    else if (c != '\0')
                    {
                       // secureStringPassword.AppendChar(c);
                        secret.Append(c);
                    }

                    // handle unicodeChar
                }
                return new ClientCredential(clientId.ToString(), secret.ToString());// new SecureClientSecret(secureStringPassword));

            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        //   public string TenantId { get; set; }
        //   public ClientCredential AzureADServiceCredentials { get; set; }
        public async Task<string> GetTokenFromClientSecret(string authority, string resource)
        {
            if (UseMSI)
            {
                var section = _config.Settings.Sections["AzureResourceManager"].Parameters;
                var http = new HttpClient();
                var req = new HttpRequestMessage(HttpMethod.Get, $"http://localhost:{section["AzureADMSIPort"].Value}/oauth2/token?resource={resource}");
                req.Headers.TryAddWithoutValidation("Metadata", "true");

                var tokenresponse = await http.SendAsync(req);

                return JToken.Parse(await tokenresponse.Content.ReadAsStringAsync()).SelectToken("$.access_token").ToString();

            }

            var authContext = new AuthenticationContext(authority);
            var result = await authContext.AcquireTokenAsync(resource, this.CreateSecureCredentials());
            return result.AccessToken;
        }

        public ClientCredential CreateSecureCredentials()
        {

            var section = _config.Settings.Sections["AzureResourceManager"].Parameters;
            return ParseSecureString(section["AzureADServicePrincipal"].DecryptValue());
        }
        public async Task<string> GetAccessToken()
        {
            var section = _config.Settings.Sections["AzureResourceManager"].Parameters;

            if (UseMSI)
            {
                logger.LogInformation("Using MSI at {host} to get token for management.azure.com", $"http://localhost:{section["AzureADMSIPort"].Value}");


                var http = new HttpClient();
                var req = new HttpRequestMessage(HttpMethod.Get,$"http://localhost:{section["AzureADMSIPort"].Value}/oauth2/token?resource=https://management.azure.com/");
                req.Headers.TryAddWithoutValidation("Metadata", "true");

                var tokenresponse = await http.SendAsync(req);

                if(tokenresponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    logger.LogInformation("Succeded for MSI at {host} to get token for management.azure.com", $"http://localhost:{section["AzureADMSIPort"].Value}");
                }

                tokenresponse.EnsureSuccessStatusCode();

                return JToken.Parse(await tokenresponse.Content.ReadAsStringAsync()).SelectToken("$.access_token").ToString();

            }
           
          

            var ctx = new AuthenticationContext($"https://login.microsoftonline.com/{section["TenantId"].Value}", _cache);

            var token = await ctx.AcquireTokenAsync("https://management.azure.com/", ParseSecureString(section["AzureADServicePrincipal"].DecryptValue()));

            return token.AccessToken;

        }

        public bool UseMSI => string.IsNullOrEmpty(_config?.Settings?.Sections["AzureResourceManager"]?.Parameters["AzureADServicePrincipal"]?.Value);


    }
}
