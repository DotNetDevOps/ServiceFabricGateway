using DotNetDevOps.ServiceFabric.Hosting;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using Microsoft.ServiceFabric.Services.Remoting.Runtime;
using Microsoft.ServiceFabric.Services.Runtime;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using SInnovations.ServiceFabric.Storage.Configuration;
using System;
using System.Collections.Generic;
using System.Fabric;
using System.Threading.Tasks;

[assembly: FabricTransportServiceRemotingProvider(RemotingClientVersion = RemotingClientVersion.V2_1, RemotingListenerVersion = RemotingListenerVersion.V2_1)]

namespace SInnovations.ServiceFabric.Storage.Services
{

    public interface IApplicationStorageService : IService
    {
        Task<string> GetApplicationStorageSharedAccessSignature();
        Task<string> GetApplicationStorageAccountNameAsync();
        Task<string> GetApplicationStorageCertificateThumbprint();
    }


   
    public class ApplicationStorageService : StatelessService, IApplicationStorageService, IDataProtectionStoreService
    {
        private readonly AzureADConfiguration azureAD;

        protected StorageConfiguration Storage { get; set; }
        public ApplicationStorageService(StatelessServiceContext serviceContext,
            AzureADConfiguration azureAD ,StorageConfiguration storage) : base(serviceContext)
        {
            this.azureAD = azureAD;
            Storage = storage;
        }



        protected override IEnumerable<ServiceInstanceListener> CreateServiceInstanceListeners()
        {
            return this.CreateServiceRemotingInstanceListeners();
            // return new[] { new ServiceInstanceListener(Factory) };
           //   return new[] { new ServiceInstanceListener(context => this.CreateServiceRemotingListener(context),"RPC") };

            //return new[]
            //{
            //     new ServiceInstanceListener((c) =>
            //     {
            //         return new FabricTransportServiceRemotingListener(c, this);

            //     },"RPC")
            // };
        }

        //private ICommunicationListener Factory(StatelessServiceContext arg)
        //{
            
        //    return new FabricTransportServiceRemotingListener(arg, this, new FabricTransportListenerSettings
        //    {
        //         EndpointResourceName = "ServiceEndpoint",
        //         KeepAliveTimeout = 
        //    });
        //}

        public async Task<string> GetApplicationStorageSharedAccessSignature()
        {
            var a = await Storage.GetApplicationStorageAccountAsync();

            return a.GetSharedAccessSignature(new SharedAccessAccountPolicy
            {
                Permissions = SharedAccessAccountPermissions.Add | SharedAccessAccountPermissions.Create | SharedAccessAccountPermissions.Delete | SharedAccessAccountPermissions.List | SharedAccessAccountPermissions.ProcessMessages | SharedAccessAccountPermissions.Read | SharedAccessAccountPermissions.Update | SharedAccessAccountPermissions.Write,
                ResourceTypes = SharedAccessAccountResourceTypes.Container | SharedAccessAccountResourceTypes.Object | SharedAccessAccountResourceTypes.Service,
                Services = SharedAccessAccountServices.Blob | SharedAccessAccountServices.File | SharedAccessAccountServices.Queue | SharedAccessAccountServices.Table,
        //        SharedAccessStartTime = DateTimeOffset.UtcNow.AddMinutes(-5),
                SharedAccessExpiryTime = DateTimeOffset.UtcNow.AddMonths(3)
            });
        }

        public async Task<string> GetApplicationStorageAccountNameAsync()
        {
            var a = await Storage.GetApplicationStorageAccountAsync();
            return a.Credentials.AccountName;
        }

        public Task<string> GetApplicationStorageCertificateThumbprint()
        {
            return Task.FromResult(
                this.Context.CodePackageActivationContext.GetConfigurationPackageObject("Config").Settings.Sections["AzureResourceManager"].Parameters["SecretsCertificateThumbprint"].Value);

        }

        public async Task<string> GetApplicationSasUri()
        {
            var a = await Storage.GetApplicationStorageAccountAsync();
            var c = a.CreateCloudBlobClient().GetContainerReference("dataprotection");
            await c.CreateIfNotExistsAsync();
            return c.Uri + c.GetSharedAccessSignature(new Microsoft.WindowsAzure.Storage.Blob.SharedAccessBlobPolicy { Permissions =  SharedAccessBlobPermissions.Write| SharedAccessBlobPermissions.Read| SharedAccessBlobPermissions.Create | SharedAccessBlobPermissions.Add, SharedAccessExpiryTime =DateTimeOffset.UtcNow.AddYears(1) });
        }

        public Task<string> GetVaultTokenAsync(string authority, string resource, string scope)
        {
            return this.azureAD.GetTokenFromClientSecret(null, resource);
        }
    }
}
