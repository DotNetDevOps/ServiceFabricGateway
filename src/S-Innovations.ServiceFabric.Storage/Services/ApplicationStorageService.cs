﻿using System;
using System.Collections.Generic;
using System.Fabric;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.ServiceFabric.Services.Communication.FabricTransport.Runtime;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport.Runtime;
using Microsoft.ServiceFabric.Services.Remoting.Runtime;
using Microsoft.ServiceFabric.Services.Runtime;
using Microsoft.WindowsAzure.Storage;
using SInnovations.ServiceFabric.Storage.Configuration;

namespace SInnovations.ServiceFabric.Storage.Services
{

    public interface IApplicationStorageService : IService
    {
        Task<string> GetApplicationStorageSharedAccessSignature();
    }


   
    public class ApplicationStorageService : StatelessService, IApplicationStorageService
    {
        protected StorageConfiguration Storage { get; set; }
        public ApplicationStorageService(StatelessServiceContext serviceContext, StorageConfiguration storage) : base(serviceContext)
        {
            Storage = storage;
        }



        protected override IEnumerable<ServiceInstanceListener> CreateServiceInstanceListeners()
        {
           // return new[] { new ServiceInstanceListener(Factory) };
            return new[] { new ServiceInstanceListener(context => this.CreateServiceRemotingListener(context),"RPC") };
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
                SharedAccessStartTime = DateTimeOffset.UtcNow,
                SharedAccessExpiryTime = DateTimeOffset.UtcNow.AddDays(1)
            });
        }
    }
}