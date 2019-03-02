using DotNetDevOps.ServiceFabric.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using SInnovations.LetsEncrypt;
using SInnovations.ServiceFabric.GatewayService.Configuration;
using SInnovations.ServiceFabric.GatewayService.Services;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Configuration;
using SInnovations.ServiceFabric.ResourceProvider;
using SInnovations.ServiceFabric.Storage.Configuration;
using SInnovations.ServiceFabric.Storage.Extensions;
using SInnovations.ServiceFabric.Storage.Services;
using System;
using System.Threading;
using System.Threading.Tasks;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Extensions;
using System.IO;
using System.Reflection;
using Microsoft.AspNetCore.Hosting.Internal;

namespace SInnovations.ServiceFabric.GatewayService
{




    public class Program
    {
        /// <summary>
        /// Event Handler delegate to log if an unhandled AppDomain exception occurs.
        /// </summary>
        /// <param name="sender">the sender</param>
        /// <param name="e">the exception details</param>
        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            Exception ex = e.ExceptionObject as Exception;
          //  ServiceEventSource.Current.UnhandledException(ex.GetType().Name, ex.Message, ex.StackTrace);
        }

        /// <summary>
        /// Event Handler delegate to log if an unobserved task exception occurs.
        /// </summary>
        /// <param name="sender">the sender</param>
        /// <param name="e">the exception details</param>
        /// <remarks>
        /// We intentionally do not mark the exception as Observed, which would prevent the process from being terminated.
        /// We want the unobserved exception to take out the process. Note, as of .NET 4.5 this relies on the ThrowUnobservedTaskExceptions
        /// runtime configuration in the host App.Config settings.
        /// </remarks>
        private static void TaskScheduler_UnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
          //  ServiceEventSource.Current.UnobservedTaskException(e.Exception?.GetType().Name, e.Exception?.Message, e.Exception?.StackTrace);

            AggregateException flattened = e.Exception?.Flatten();
            foreach (Exception ex in flattened?.InnerExceptions)
            {
             //   ServiceEventSource.Current.UnobservedTaskException(ex.GetType().Name, ex.Message, ex.StackTrace);
            }

            // Marking as observed to prevent process exit.
           // e.SetObserved();
        }

      

        public static async Task Main(string[] args)
        {

           
            Environment.SetEnvironmentVariable("LD_LIBRARY_PATH", null);
            // var cp = CertificateProvider.GetProvider("BouncyCastle");

            // Setup unhandled exception handlers.
            TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;

            using (var host = new FabricHostBuilder(args)

                //Add fabric configuration provider
                .ConfigureAppConfiguration((context, configurationBuilder) =>
                {

                    configurationBuilder.AddServiceFabricConfig("Config");

                })
               //Setup services that exists on root, shared in all services
               .ConfigureServices((context, services) =>
               {

                  

                   services.AddOptions();

                   services.AddServiceFabricApplicationStorage(true);

                   services.AddSingleton<AzureADConfiguration>();
                   services.AddSingleton<KeyVaultSecretManager>();
                   services.AddSingleton<IConfigurationBuilderExtension, KeyVaultSecretManager>();

                   services.WithLetsEncryptService(new LetsEncryptServiceOptions
                   {
                       BaseUri = Certes.Acme.WellKnownServers.LetsEncryptV2.AbsoluteUri// "https://acme-v01.api.letsencrypt.org"
                   });

                  

               })
                //Configure Fabric Services
                .WithStatelessService<NginxGatewayService>("GatewayServiceType")
                .WithStatelessService<ApplicationStorageService>("ApplicationStorageServiceType")
                .WithStatelessService<KeyVaultService>("KeyVaultServiceType")
                .WithStatelessService<ResourceProviderService>("ResourceProviderServiceType")
                .WithStatefullService<GatewayManagementService>("GatewayManagementServiceType")
                //Configure IOptions
                .Configure<KeyVaultOptions>("KeyVault")
                //Configure Logging
                .ConfigureSerilogging(
                    (context, logConfiguration) =>
                             logConfiguration.MinimumLevel.Debug()
                             .Enrich.FromLogContext()
                             .WriteTo.File("trace.log", retainedFileCountLimit: 5, fileSizeLimitBytes: 1024 * 1024 * 10)
                             .WriteTo.LiterateConsole(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message}{NewLine}{Exception}{NewLine}")
                          //   .WriteTo.ApplicationInsightsTraces(Environment.GetEnvironmentVariable("APPLICATION_INSIGHTS"), Serilog.Events.LogEventLevel.Information)
                )
                .ConfigureApplicationInsights()
                //BuildApplication
                .Build()
                )
            {

                try
                {
                  
                    await host.RunAsync();
                }
                catch (Exception ex)
                {

                    //  System.IO.File.WriteAllText("env.log", JsonConvert.SerializeObject( Environment.GetEnvironmentVariables()));
                    System.IO.File.WriteAllText("err.log", ex.ToString());
                    throw;

                }


            }
           




        }

         
    }
}
