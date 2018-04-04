using Unity;
using SInnovations.LetsEncrypt;
using SInnovations.LetsEncrypt.Clients;
using SInnovations.LetsEncrypt.Services;
using SInnovations.LetsEncrypt.Services.Defaults;
using SInnovations.LetsEncrypt.Stores;
using SInnovations.LetsEncrypt.Stores.Defaults;
using SInnovations.ServiceFabric.Unity;
using Certes;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{
    public static class DsnExtensions
    {
        public static IUnityContainer WithLetsEncryptService(this IUnityContainer container, LetsEncryptServiceOptions options)
        {
            container.RegisterInstance(options);
            container.AddScoped<IRS256SignerStore, SignersStore>();
          //  container.AddScoped<IRS256SignerService, DefaultRS256SignerService>();
            container.AddScoped<IAcmeClientService<AcmeContext>, CertesAcmeClientService>();
            container.AddScoped<IAcmeRegistrationStore, InMemoryAcmeRegistrationStore>();
            
            container.AddScoped<ILetsEncryptChallengeService<AcmeContext>, CertesChallengeService>();
            container.AddScoped<ICloudFlareZoneService, CloudFlareZoneServiceWrapper>();
            container.AddScoped<IOrdersService, OrdersServicesWrapper>();
          
            container.AddScoped<IDnsClient, CloudFlareDNSClient>();

          //  container.AddScoped<DnsMadeEasyClientCredetials, DnsMadeEasyOptions>();
            container.AddScoped<LetsEncryptService<AcmeClient>>();

            return container;
        }
    }










}
