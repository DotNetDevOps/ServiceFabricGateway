using Certes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SInnovations.LetsEncrypt;
using SInnovations.LetsEncrypt.Clients;
using SInnovations.LetsEncrypt.Services;
using SInnovations.LetsEncrypt.Services.Defaults;
using SInnovations.LetsEncrypt.Stores;
using SInnovations.LetsEncrypt.Stores.Defaults;

namespace SInnovations.ServiceFabric.GatewayService.Configuration
{
    public static class DsnExtensions
    {
        public static IServiceCollection WithLetsEncryptService(this IServiceCollection container, LetsEncryptServiceOptions options)
        {
          
                container.AddSingleton(options);
                container.AddScoped<IRS256SignerStore, SignersStore>();
                //  container.AddScoped<IRS256SignerService, DefaultRS256SignerService>();
                container.AddScoped<IAcmeClientService<AcmeContext>, CertesAcmeClientService>();
                container.AddScoped<IAcmeRegistrationStore, InMemoryAcmeRegistrationStore>();

                container.AddScoped<ILetsEncryptChallengeService<AcmeContext>, CertesChallengeService>();
                container.AddScoped<ICloudFlareZoneService, CloudFlareZoneServiceWrapper>();
                container.AddScoped<IOrdersService, OrdersServicesWrapper>();

                container.AddScoped<IDnsClient>(sp=>sp.GetRequiredService< CloudFlareDNSClient>());

                container.AddHttpClient<CloudFlareDNSClient>();

                //  container.AddScoped<DnsMadeEasyClientCredetials, DnsMadeEasyOptions>();
                container.AddScoped<LetsEncryptService<AcmeClient>>();
                container.AddScoped<LetsEncryptService<AcmeContext>>();
            return container;
        }
    }










}
