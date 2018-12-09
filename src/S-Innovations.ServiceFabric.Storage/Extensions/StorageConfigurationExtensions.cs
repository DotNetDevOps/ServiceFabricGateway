using IdentityModel;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using SInnovations.ServiceFabric.Storage.Configuration;
using SInnovations.ServiceFabric.Storage.Services;
using System;
using System.Diagnostics;
using System.Fabric;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SInnovations.ServiceFabric.Storage.Extensions
{
    public static class StorageConfigurationExtensions
    {

        public static IServiceCollection AddServiceFabricApplicationStorage(this IServiceCollection container, bool useFileCache = true)
        {
            
           // container.RegisterType<IKeyManager, XmlKeyManager>();
          
            if(useFileCache)
            {
                container
                  .AddSingleton<TokenCache>(sp => new FileCache(sp.GetService<ILoggerFactory>(), sp.GetService<IDataProtectionProvider>()))
                  .AddSingleton(sp => DataProtectionProvider.Create(sp.GetService<ICodePackageActivationContext>().ApplicationName));

            }
            else
            {
                container.AddSingleton(new TokenCache());
            }


            return container
                .AddSingleton<StorageConfiguration>();


            
        }

        public static IServiceCollection AddApplicationStorageDataProtection(this IServiceCollection services, IApplicationStorageService storage, X509Certificate2 cert =null, string applicationName =null, params X509Certificate2[] unprotects )
        {
            if (storage != null)
            {
              

                try
                {
                    if (string.IsNullOrEmpty(applicationName))
                    {
                        StackTrace stackTrace = new StackTrace();
                        var method = stackTrace.GetFrame(1).GetMethod();
                       applicationName = method.DeclaringType.Assembly.GetName().Name;
                    }


                   // var storage = container.GetService<IApplicationStorageService>();

                    if (cert == null)
                    {
                        var thumbprint = storage.GetApplicationStorageCertificateThumbprint().GetAwaiter().GetResult();

                        cert = X509.LocalMachine.My.Thumbprint.Find(thumbprint, validOnly: false).FirstOrDefault();
                    }

                  
                    var token = storage.GetApplicationStorageSharedAccessSignature().GetAwaiter().GetResult();
                    var name = storage.GetApplicationStorageAccountNameAsync().GetAwaiter().GetResult();
                    var a = new CloudStorageAccount(new StorageCredentials(token), name, null, true);
                    var c = a.CreateCloudBlobClient().GetContainerReference("dataprotection");
                    c.CreateIfNotExistsAsync().Wait();

                    services.AddDataProtection()
                     .SetApplicationName(applicationName)
                     .ProtectKeysWithCertificate(cert)
                     .UnprotectKeysWithAnyCertificate(unprotects)
                     .PersistKeysToAzureBlobStorage(c.GetBlockBlobReference(applicationName+".csrf"));
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                    throw;
                }
            }

            return services;
        }
    }
}
