﻿using System;
using System.Collections.Generic;
using System.Fabric;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace SInnovations.ServiceFabric.Storage.Configuration
{
    public class AzureADConfiguration
    {
        private readonly TokenCache _cache;
        private readonly ConfigurationPackage _config;
        // private readonly 
        public AzureADConfiguration(ConfigurationPackage configurationPackage, TokenCache cache)
        {
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

            var ctx = new AuthenticationContext($"https://login.microsoftonline.com/{section["TenantId"].Value}", _cache);

            var token = await ctx.AcquireTokenAsync("https://management.azure.com/", ParseSecureString(section["AzureADServicePrincipal"].DecryptValue()));

            return token.AccessToken;

        }


    }
}
