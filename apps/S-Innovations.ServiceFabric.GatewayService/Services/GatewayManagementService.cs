using Microsoft.ServiceFabric.Actors;
using Microsoft.ServiceFabric.Actors.Runtime;
using Microsoft.WindowsAzure.Storage;
using SInnovations.LetsEncrypt;
using SInnovations.ServiceFabric.Gateway.Actors;
using SInnovations.ServiceFabric.Gateway.Common.Model;
using SInnovations.ServiceFabric.Gateway.Model;
using SInnovations.ServiceFabric.Storage.Configuration;
using System;
using System.Collections.Generic;
using System.Fabric;
using System.Fabric.Description;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.WindowsAzure.Storage.Blob;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certes;
using Certes.Acme;
using Certes.Pkcs;
using System.Security.Cryptography;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1;
using System.Collections.Concurrent;
using Certes.Acme.Resource;
using SInnovations.ServiceFabric.GatewayService.Configuration;
using Microsoft.ServiceFabric.Services.Runtime;
using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Data.Collections;
using System.Threading;
using Microsoft.ServiceFabric.Data;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Remoting.Runtime;
using SInnovations.LetsEncrypt.Services.Defaults;
using SInnovations.LetsEncrypt.Stores;
using SInnovations.LetsEncrypt.Services;
using Microsoft.Extensions.Logging;
using System.Runtime.CompilerServices;
using Newtonsoft.Json.Linq;

namespace SInnovations.ServiceFabric.GatewayService.Services
{

    public static class LoggingExtension
    {
        public static void BeginMethod(this ILogger logger
                                , [CallerMemberName] string memberName = "")
        {
            logger.LogInformation($"BEGIN {memberName}");
        }
        public static void EndMethod(this ILogger logger
                               , [CallerMemberName] string memberName = "")
        {
            logger.LogInformation($"END {memberName}");
        }
        public static void Throwing(this ILogger logger, Exception ex
                             , [CallerMemberName] string memberName = "")
        {
            logger.LogWarning(ex, $"Throwing {memberName}");
        }
        public static IDisposable BeginEnd(this ILogger logger, string message, object[] args, [CallerMemberName] string memberName = "")
        {
            logger.LogInformation($"BEGIN {memberName} | {message}", args);
            return new BeginEndScope(logger, memberName);
        }
    }
    public class BeginEndScope : IDisposable
    {
        private ILogger logger;
        private string memberName;

        public BeginEndScope(ILogger logger, string memberName)
        {
            this.logger = logger;
            this.memberName = memberName;
        }

        public void Dispose()
        {
            logger.LogInformation($"END {memberName}");
        }
    }

    public interface IServiceFabricIRS256SignerStore : IService
    {
        Task<bool> ExistsAsync(string dnsIdentifier);

        Task<string> GetSignerAsync(string dnsIdentifier);
        Task SetSigner(string dnsIdentifier, string cert);
    }
    public interface IServiceFabricIOrdersService : IService
    {
        Task<string> GetRemoteLocationAsync(string topLevelDomain);
        Task ClearOrderAsync(string topLevelDomain);
        Task SetRemoteLocationAsync(string domain, string location);
    }
    public class EndpointsModel
    {
        public Dictionary<string,string> Endpoints { get; set; }

    }
    public sealed class GatewayManagementService : StatefulService,
        IGatewayManagementService, ICloudFlareZoneService, IServiceFabricIOrdersService, IServiceFabricIRS256SignerStore
    {
        public const string STATE_LAST_UPDATED_NAME = "lastUpdated";
        public const string STATE_PROXY_DATA_NAME = "ProxyDictionary";
        public const string STATE_CERTS_DATA_NAME = "CertsDictionary";
        public const string STATE_CERTS_QUEUE_DATA_NAME = "CertsQueue";

        //  private readonly CloudFlareZoneService cloudFlareZoneService;
        private readonly StorageConfiguration storage;
        private readonly FabricClient fabricClient;
        private readonly LetsEncryptService<AcmeContext> letsEncrypt;
        private readonly IAcmeClientService<AcmeContext> acmeClientService;
        private readonly ILogger logger;

        private CloudStorageAccount StorageAccount { get; set; }

        public GatewayManagementService(
            StatefulServiceContext context,
            StorageConfiguration storage,
            FabricClient fabricClient,
            LetsEncryptService<AcmeContext> letsEncrypt,
            IAcmeClientService<AcmeContext> acmeClientService,
            ILoggerFactory loggerFactory)
            : base(context)
        {

            this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
            this.fabricClient = fabricClient ?? throw new ArgumentNullException(nameof(fabricClient));
            this.letsEncrypt = letsEncrypt ?? throw new ArgumentNullException(nameof(letsEncrypt));
            this.acmeClientService = acmeClientService ?? throw new ArgumentNullException(nameof(acmeClientService));

            this.logger = loggerFactory.CreateLogger<GatewayManagementService>();
        }

        protected override IEnumerable<ServiceReplicaListener> CreateServiceReplicaListeners()
        {
            return this.CreateServiceRemotingReplicaListeners();
        }

        protected override async Task RunAsync(CancellationToken cancellationToken)
        {
            logger.LogInformation("Running Gatway Management Service");
            await Task.Delay(TimeSpan.FromMinutes(2));

            StorageAccount = await storage.GetApplicationStorageAccountAsync();

            var certs = await StateManager.GetOrAddAsync<IReliableDictionary<string, CertGenerationState>>(STATE_CERTS_DATA_NAME);
            var store = await StateManager.GetOrAddAsync<IReliableQueue<string>>(STATE_CERTS_QUEUE_DATA_NAME).ConfigureAwait(false);
            var certContainer = StorageAccount.CreateCloudBlobClient().GetContainerReference("certs");
            await certContainer.CreateIfNotExistsAsync();



            while (!cancellationToken.IsCancellationRequested)
            {


                var hostname = "";


                using (var tx = StateManager.CreateTransaction())
                {
                    try
                    {
                        var itemFromQueue = await store.TryDequeueAsync(tx).ConfigureAwait(false);
                        if (!itemFromQueue.HasValue)
                        {
                            await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);
                            continue;
                        }

                        hostname = itemFromQueue.Value;
                    }
                    catch (Exception ex)
                    {
                        continue;
                    }
                    await tx.CommitAsync();
                }

                try
                {

                    await CreateCertificateAsync(hostname, store, certs, certContainer, cancellationToken);

                }
                catch (Exception ex)
                {
                    using (var tx = StateManager.CreateTransaction())
                    {
                        await store.EnqueueAsync(tx, hostname);
                    }

                    await Task.Delay(TimeSpan.FromSeconds(60), cancellationToken).ConfigureAwait(false);
                }


            }
        }
        public async Task CreateCertificateAsync(string hostname, IReliableQueue<string> store, IReliableDictionary<string, CertGenerationState> certs, CloudBlobContainer certContainer, CancellationToken cancellationToken)
        {
            logger.LogInformation("Begin to create certificate for {hostname}", hostname);

            //We will assume wildcard certs.





            CertGenerationState certInfo = null;

            using (var tx1 = StateManager.CreateTransaction())
            {
                var certInfoLookup = await certs.TryGetValueAsync(tx1, hostname, LockMode.Default, GatewayManagementServiceClient.TimeoutSpan, CancellationToken.None);
                certInfo = certInfoLookup.Value;

                if (certInfo.Completed)
                {
                    logger.LogInformation("certificate for {hostname} already completed", hostname);
                    return;
                }
            }



            var certCN = certInfo.SslOptions.UseHttp01Challenge ? hostname : string.Join(".", hostname.Split('.').TakeLast(2));

            var certBlob = certContainer.GetBlockBlobReference($"{certCN}.crt");
            var fullchain = certContainer.GetBlockBlobReference($"{certCN}.fullchain.pem");
            var keyBlob = certContainer.GetBlockBlobReference($"{certCN}.key");



            if (certInfo.Counter < 3 && ((await Task.WhenAll(certBlob.ExistsAsync(), keyBlob.ExistsAsync(), fullchain.ExistsAsync())).Any(t => t == false) ||
                 await CertExpiredAsync(certBlob)))
            {

                if (certInfo.SslOptions.UseHttp01Challenge)
                {
                    await HandleHttpChallengeAsync(store, certs, hostname, certBlob, fullchain, keyBlob, certInfo);
                }
                else
                {
                    await HandleDnsChallengeAsync(certs, certContainer, hostname, certBlob, fullchain, keyBlob, certInfo);
                }
            }
            else
            {
                if (certInfo.Counter == 3)
                {
                    logger.LogWarning("Failed to create certificate at retries {Count}", certInfo.Counter);
                }

                using (var tx = StateManager.CreateTransaction())
                {
                    logger.LogInformation("Completing the certificate generation for {hostname}", hostname);
                    await certs.SetAsync(tx, hostname, certInfo.Complete());
                    await tx.CommitAsync();
                    _lastUpdated = DateTimeOffset.UtcNow;
                }
            }
            logger.LogInformation("End to create certificate for {hostname}", hostname);

        }
        // public static AcmeClient client = new AcmeClient(WellKnownServers.LetsEncryptV2);
        //  public static ConcurrentDictionary<string, Task<AcmeAccount>> _acmeaccounts = new ConcurrentDictionary<string, Task<AcmeAccount>>();

        private async Task HandleDnsChallengeAsync(IReliableDictionary<string, CertGenerationState> certs, CloudBlobContainer certsContainer, string hostname, CloudBlockBlob certBlob, CloudBlockBlob fullchain, CloudBlockBlob keyBlob, CertGenerationState certInfo)
        {

            logger.LogInformation("Handing DNS Challenge {hostname}", hostname);
            try
            {

                var cert = await letsEncrypt.GenerateCertPairAsync(new GenerateCertificateRequestOptions
                {
                    DnsIdentifier = certInfo.HostName,
                    SignerEmail = certInfo.SslOptions.SignerEmail,
                    PfxPassword = ""
                });

                await keyBlob.UploadFromByteArrayAsync(cert.Item1, 0, cert.Item1.Length);
                await certBlob.UploadFromByteArrayAsync(cert.Item2, 0, cert.Item2.Length);
                await fullchain.UploadFromByteArrayAsync(cert.Item3, 0, cert.Item3.Length);

                using (ITransaction tx = StateManager.CreateTransaction())
                {
                    await certs.SetAsync(tx, hostname, certInfo.Complete(), GatewayManagementServiceClient.TimeoutSpan, CancellationToken.None);
                    await tx.CommitAsync();
                    _lastUpdated = DateTimeOffset.UtcNow;
                }
            }
            catch (Exception ex)
            {
                using (ITransaction tx = StateManager.CreateTransaction())
                {
                    await certs.SetAsync(tx, hostname, certInfo.Increment(), GatewayManagementServiceClient.TimeoutSpan, CancellationToken.None);
                    await tx.CommitAsync();
                }
                await certsContainer.GetBlockBlobReference($"{hostname}.err").UploadTextAsync(ex.ToString());

            }
        }
        //private static async Task<AcmeAccount> AcmeAccountFactory(string email)
        //{

        //    // Create new registration
        //    var account1 = await client.NewRegistraton("mailto:" + email);


        //    // Accept terms of services
        //    account1.Data.Agreement = account1.GetTermsOfServiceUri();
        //    account1 = await client.UpdateRegistration(account1);
        //    return account1;

        //}
        private async Task HandleHttpChallengeAsync(IReliableQueue<string> store, IReliableDictionary<string, CertGenerationState> certs,
            string hostname, CloudBlockBlob certBlob, CloudBlockBlob fullchain, CloudBlockBlob keyBlob, CertGenerationState certInfo)
        {
            logger.LogInformation("Handing Http Challenge {hostname}", hostname);


            //   var client = new AcmeClient(WellKnownServers.LetsEncryptV2);


            //   var gateway = GatewayManagementServiceClient.GetProxy<IServiceFabricIRS256SignerStore>(
            //           $"{this.Context.CodePackageActivationContext.ApplicationName}/{nameof(GatewayManagementService)}", certInfo.SslOptions.SignerEmail);

            //if (await gateway.ExistsAsync(certInfo.SslOptions.SignerEmail))
            //{
            //    client.Use(KeyInfo.From(new MemoryStream(Encoding.ASCII.GetBytes(await gateway.GetSignerAsync(certInfo.SslOptions.SignerEmail)))));
            //}
            //else
            //{
            //    var ctx = new Certes.AcmeContext(WellKnownServers.LetsEncryptV2);

            //    var tos = ctx.TermsOfService();

            //    var ac = await ctx.NewAccount(certInfo.SslOptions.SignerEmail, true);

            //    await ac.Update(
            //        contact: new[] { $"mailto:{certInfo.SslOptions.SignerEmail}" },
            //        agreeTermsOfService: true);


            //    var pem = ctx.AccountKey.ToPem();
            //    //  var ms = new MemoryStream(Encoding.ASCII.GetBytes(pem));
            //    await gateway.SetSigner(certInfo.SslOptions.SignerEmail, pem);
            //    client.Use(KeyInfo.From(new MemoryStream(Encoding.ASCII.GetBytes(pem))));
            //}


            var context = await acmeClientService.CreateClientAsync(WellKnownServers.LetsEncryptV2.AbsoluteUri, null, certInfo.SslOptions.SignerEmail);//;

            var accountContext = await context.Account();
            var account = await accountContext.Resource();
            logger.LogInformation("Handing Http Challenge {hostname} with info {@HttpChallengeInfo} using {@account}", hostname, certInfo.HttpChallengeInfo, account);

            if (certInfo.HttpChallengeInfo == null)
            {
                try
                {
                    //using (var client = new AcmeClient(WellKnownServers.LetsEncryptStaging))
                    {






                        {
                            var orderlocation = await accountContext.Orders();
                            if (orderlocation.Location != null)
                            {
                                logger.LogInformation("order list {orderLocation}", orderlocation.Location);
                                var orders = await orderlocation.Resource();


                                foreach (var order in orders.Orders)
                                {
                                    logger.LogInformation("order {orderLocation}", order.AbsoluteUri);
                                }

                                var ordersall = await orderlocation.Orders();
                                foreach (var order in ordersall)
                                {
                                    var orderr = await order.Resource();
                                    logger.LogInformation("{@order", orderr);
                                }
                            }
                        }
                        {
                            var newOrder = await context.NewOrder(new[] { hostname });
                            logger.LogInformation("created a new order {order}", newOrder.Location);

                            var authorizations = await newOrder.Authorizations();

                            using (ITransaction tx = StateManager.CreateTransaction())
                            {
                                await certs.SetAsync(tx, hostname, certInfo.SetOrderLocation(newOrder.Location.AbsoluteUri));

                                await tx.CommitAsync();
                            }


                            foreach (var authz in authorizations)
                            {
                                logger.LogInformation("Authz = {AuthzLocation}", authz.Location);

                                foreach (var challange in await authz.Challenges())
                                {
                                    logger.LogInformation("Handing Http Challenge {hostname} challange {challangeType} uri {uri}", hostname, challange.Type, challange.Location);
                                }

                                var http = await authz.Http();

                                logger.LogInformation("http challenge for {hostname} {@http}", hostname, http);

                                using (ITransaction tx = StateManager.CreateTransaction())
                                {
                                    var a = new CertHttpChallengeInfo
                                    {
                                        Token = http.Token,
                                        KeyAuthString = http.KeyAuthz// client.ComputeKeyAuthorization(httpChallengeInfo),

                                    };

                                    logger.LogInformation("Handing Http Challenge {hostname} ComputeKeyAuthorization complete {@CertHttpChallengeInfo}", hostname, a);

                                    await certs.SetAsync(tx, hostname, certInfo.SetCertHttpChallengeInfo(a));

                                    await tx.CommitAsync();
                                }



                                using (ITransaction tx = StateManager.CreateTransaction())
                                {
                                    var challenge = await http.Validate();
                                    // var complet = await client.CompleteChallenge(httpChallengeInfo);

                                    logger.LogInformation("Handing Http Challenge {hostname} completing at {url} with {@challenge}", hostname, challenge.Url, challenge);
                                    await certs.SetAsync(tx, hostname, certInfo.SetCertHttpChallengeLocation(challenge.Url.AbsoluteUri));
                                    await store.EnqueueAsync(tx, hostname);
                                    await tx.CommitAsync();
                                }

                            }




                            //  var order = await context.NewOrder(new[] { hostname });
                            //  var ctx = await order.Authorization("a", IdentifierType.Dns);


                            // Initialize authorization
                            //var authz = await client.NewAuthorization(new AuthorizationIdentifier
                            //{
                            //    Type = AuthorizationIdentifierTypes.Dns,
                            //    Value = hostname
                            //});

                            //logger.LogInformation("Handing Http Challenge {hostname} created authorization {@authorization}", hostname, authz.Json);
                            //foreach (var challange in authorizations.Data.Challenges)
                            //{
                            //    logger.LogInformation("Handing Http Challenge {hostname} challange uri {uri}", hostname, challange.Uri);
                            //}

                            //var httpChallengeInfo = authz.Data.Challenges.First(c => c.Type == ChallengeTypes.Http01);




                        }

                    }
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to handle http {hostname}", hostname);
                }
            }
            else
            {
                // using (var client = new AcmeClient(WellKnownServers.LetsEncryptStaging))
                {
                    await Task.Delay(2000);

                    var orderContext = context.Order(new Uri(certInfo.OrderLocation));
                    var order = await orderContext.Resource();

                 
                    var authorizations = await orderContext.Authorizations();
                    var auths = await Task.WhenAll(authorizations.Select(c => c.Http()));
                    var challenges = await Task.WhenAll(auths.Select(c => c.Resource()));
                    var status = challenges.Select(c => c.Status.Value).All(c => c != ChallengeStatus.Pending);
                    var allvalid= challenges.Select(c => c.Status.Value).All(c => c == ChallengeStatus.Valid);
                    logger.LogInformation( "Completing challenges {@challenges}", challenges);

                    if (status)
                    {
                        if(allvalid)
                        {

                            try
                            {
                                var certKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
                                order = await orderContext.Finalize(
                                  new CsrInfo
                                  {
                                      CountryName = "DK",
                                      State = "Capital Region",
                                      Locality = "Copenhagen",
                                      Organization = "EarthML",
                                  }, certKey);

                                if (order.Status == Certes.Acme.Resource.OrderStatus.Invalid)
                                {
                                    logger.LogWarning("Failed to create cert {hostname}, {@order}", hostname,order);
                                }

                                var certChain = await orderContext.Download();
                                //  Certes.Acme.
                                //    var cert = new CertificateInfo(certChain, certKey);
                                var cert = certChain.Certificate;


                                var pem = cert.ToPem();
                                var der = cert.ToDer();
                                //  var pfx = cert.ToPfx("cert-name", "abcd1234");

                                var keyPem = certKey.ToPem();

                                var item1 = Encoding.ASCII.GetBytes(keyPem);
                                var item2 = Encoding.ASCII.GetBytes(pem);
                                var item3 = Encoding.ASCII.GetBytes($"{certChain.Certificate.ToPem()}\n{string.Join("\n", certChain.Issuers.Select(c => c.ToPem()))}");

                                await keyBlob.UploadFromByteArrayAsync(item1, 0, item1.Length);
                                await certBlob.UploadFromByteArrayAsync(item2, 0, item2.Length);
                                await fullchain.UploadFromByteArrayAsync(item3, 0, item3.Length);

                            
                            }
                            catch (Exception ex)
                            {
                                logger.LogWarning(ex, "Failed to create cert {hostname}", hostname);
                                await keyBlob.Container.GetBlockBlobReference($"{hostname}.err").UploadTextAsync(ex.ToString());
                            }
                            finally
                            {
                                logger.LogInformation("certificates for {hostname} was complted with success", hostname);
                                using (ITransaction tx = StateManager.CreateTransaction())
                                {
                                    await certs.SetAsync(tx, hostname, certInfo.Complete());
                                    await tx.CommitAsync();
                                    _lastUpdated = DateTimeOffset.UtcNow;
                                }
                            }
                        }
                        else
                        {
                            logger.LogWarning("Handing Http Challenge {hostname} auth status={status} not valid", hostname, order.Status);
                        }
                    }
                    else
                    {
                        logger.LogWarning("Handing Http Challenge {hostname} auth status is pending, requeing for {@order}", hostname,order);
                        using (ITransaction tx = StateManager.CreateTransaction())
                        {
                            await store.EnqueueAsync(tx, hostname);
                            await tx.CommitAsync();
                        }
                    }

                      
                    //var location = new Uri(certInfo.HttpChallengeInfo.Location);

                    //// Check authorization status (use the proper challenge to check Authorization State)
                    //var authz = await client.GetAuthorization(location); // or dnsChallenge.Location

                    //logger.LogInformation("Handing Http Challenge {hostname} auth status={status}", hostname, authz.Data.Status);

                    //if (authz.Data.Status != EntityStatus.Pending)
                    //{

                    //    if (authz.Data.Status == EntityStatus.Valid)
                    //    {
                    //        try
                    //        {
                    //            // Create certificate
                    //            var csr = new CertificationRequestBuilder();
                    //            csr.AddName("CN", hostname);
                    //            var cert = await client.NewCertificate(csr);
                    //            var keyInfo = cert.Key;

                    //            var ms = new MemoryStream();
                    //            keyInfo.Save(ms);

                    //            //  cert.Issuer.Raw 

                    //            //  var keyPair = cert.Key.CreateKeyPair();

                    //            //   var pro = new AsymmetricKeyEntry()//
                    //            // Export Pfx
                    //            var pfxBuilder = cert.ToPfx();
                    //            var pfx = pfxBuilder.Build(hostname, "abcd1234");

                    //            X509Certificate2 certificate = new X509Certificate2(pfx, "abcd1234", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                    //            String pem = "-----BEGIN CERTIFICATE-----\r\n" + Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks) + "\r\n-----END CERTIFICATE-----";

                    //            //var c= certificate.GetRSAPrivateKey();
                    //            // var test = certificate.PrivateKey;
                    //            // RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)test;
                    //            // MemoryStream memoryStream = new MemoryStream();
                    //            // TextWriter streamWriter = new StreamWriter(memoryStream);
                    //            // PemWriter pemWriter = new PemWriter(streamWriter);
                    //            // AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
                    //            // pemWriter.WriteObject(keyPair.Private);
                    //            // streamWriter.Flush();
                    //            // string output = Encoding.ASCII.GetString(memoryStream.GetBuffer()).Trim();
                    //            // int index_of_footer = output.IndexOf("-----END RSA PRIVATE KEY-----");
                    //            // memoryStream.Close();
                    //            // streamWriter.Close();
                    //            // string PrivKey = output.Substring(0, index_of_footer + 29);

                    //            // await keyBlob.UploadTextAsync(PrivKey);
                    //            // var ms = new MemoryStream();
                    //            // var mss = new StreamWriter(ms);
                    //            // var chain = new PemWriter(mss);
                    //            // chain.WriteObject(certificate);
                    //            // mss.Flush();
                    //            // ms.Flush();
                    //            var chiancert = ms.ToArray();
                    //            await keyBlob.UploadFromByteArrayAsync(chiancert, 0, chiancert.Length);
                    //            //  await fullchain.UploadFromByteArrayAsync(cert.Raw, 0, cert.Raw.Length);
                    //            await fullchain.UploadTextAsync(pem);
                    //            var cr = certificate.Export(X509ContentType.Cert);
                    //            await certBlob.UploadFromByteArrayAsync(cr, 0, cr.Length);

                    //            //  File.WriteAllBytes("./my-free-cert.pfx", pfx);

                    //            // // Revoke certificate
                    //            //  await client.RevokeCertificate(cert);
                    //        }
                    //        catch (Exception ex)
                    //        {
                    //            logger.LogWarning(ex, "Failed to create cert {hostname}", hostname);
                    //        }
                    //        finally
                    //        {

                    //            using (ITransaction tx = StateManager.CreateTransaction())
                    //            {
                    //                await certs.SetAsync(tx, hostname, certInfo.Complete());
                    //                await tx.CommitAsync();
                    //            }
                    //        }
                    //    }
                    //    else
                    //    {
                    //        logger.LogWarning("Handing Http Challenge {hostname} auth status={status} not valid", hostname, authz.Data.Status);
                    //    }
                    //}
                    //else
                    //{
                    //    logger.LogWarning("Handing Http Challenge {hostname} auth statu is pending, requeing", hostname);
                    //    using (ITransaction tx = StateManager.CreateTransaction())
                    //    {
                    //        await store.EnqueueAsync(tx, hostname);
                    //        await tx.CommitAsync();
                    //    }
                    //}
                }
            }
        }
        private async Task<bool> CertExpiredAsync(CloudBlockBlob certBlob)
        {
            try
            {

                var bytes = new byte[certBlob.Properties.Length];
                await certBlob.DownloadToByteArrayAsync(bytes, 0);

                X509Certificate2 clientCertificate =
                     new X509Certificate2(bytes);
                return clientCertificate.NotAfter.ToUniversalTime() < DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                return true;
            }
        }

        public async Task SetupStorageServiceAsync(int instanceCount)
        {
            logger.LogInformation("Begin setting up storage services");

            var client = new FabricClient();
            var codeContext = this.Context.CodePackageActivationContext;

            var applicationName = new Uri(codeContext.ApplicationName.StartsWith("fabric:/") ? codeContext.ApplicationName : $"fabric:/{codeContext.ApplicationName}");

            var services = await client.QueryManager.GetServiceListAsync(applicationName);

            if (!services.Any(s => s.ServiceTypeName == "ApplicationStorageServiceType"))
            {

                await client.ServiceManager.CreateServiceAsync(new StatelessServiceDescription
                {
                    ServiceTypeName = "ApplicationStorageServiceType",
                    ApplicationName = applicationName,
                    ServiceName = new Uri(applicationName.ToString() + "/ApplicationStorageService"),
                    InstanceCount = instanceCount,
                    PartitionSchemeDescription = new SingletonPartitionSchemeDescription()
                });

            }

            logger.LogInformation("End setting up storage services");
        }


        public async Task RegisterGatewayServiceAsync(GatewayServiceRegistrationData data)
        {
            //Remove when upgrade cycle is done
            if (data.Key.EndsWith(data.IPAddressOrFQDN))
                data.Key = data.Key.Substring(0, data.Key.Length - 1 - data.IPAddressOrFQDN.Length);



            logger.LogInformation("Begin Registering gateway service {key} {@gatewaydata}", data.Key, data);
            try
            {
                if (data.Properties.ContainsKey("CloudFlareZoneId"))
                {

                    logger.LogInformation("Registering gateway service {key} used cloudflare", data.Key);

                    var dnsidentifiers = data.ServerName.Split(' ').Select(d => string.Join(".", d.Split('.').TakeLast(2)).ToLower()).Distinct().ToArray();
                    if (dnsidentifiers.Length == 1)
                    {
                        //Have to use the proxy to get correct partition, this is the key partition for which the proxy is added.
                        await GatewayManagementServiceClient.GetProxy<ICloudFlareZoneService>(this.Context.ServiceName.AbsoluteUri, dnsidentifiers.First())
                            .UpdateZoneIdAsync(dnsidentifiers.First(), data.Properties["CloudFlareZoneId"] as string);
                    }
                }

                var proxies = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, GatewayServiceRegistrationData>>(STATE_PROXY_DATA_NAME);


                using (var tx = this.StateManager.CreateTransaction())
                {
                    await proxies.AddOrUpdateAsync(tx, $"{data.Key}-{data.IPAddressOrFQDN}" , data, (key, old) => data);

                    await tx.CommitAsync();


                }

                try
                {
                    var notifications = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, long>>("ServiceNotifications");
                    using (var tx = this.StateManager.CreateTransaction())
                    {
                        await notifications.GetOrAddAsync(tx, data.ServiceName.AbsoluteUri, (serviceName) =>
                          {
                              logger.LogInformation("Registering notification filter for {serviceName}",serviceName);
                              var filterDescription = new ServiceNotificationFilterDescription
                              {
                                  Name = data.ServiceName // new Uri("fabric:"),
                                                          // MatchNamePrefix = true,
                                                          // MatchPrimaryChangeOnly = true
                          };

                              fabricClient.ServiceManager.ServiceNotificationFilterMatched +=  OnNotification;

                              return fabricClient.ServiceManager.RegisterServiceNotificationFilterAsync(filterDescription).GetAwaiter().GetResult();
                          });
                    }
                }catch(Exception ex)
                {
                    logger.LogWarning(ex, "Failed to register notification in Registering gateway service {key}", data.Key);
                }
              //  fabric.ServiceManager.ServiceNotificationFilterMatched += ServiceManager_ServiceNotificationFilterMatched;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Throwing in Registering gateway service {key}", data.Key);
                throw;
            }
            _lastUpdated = DateTimeOffset.UtcNow;
            logger.LogInformation("End Registering gateway service {key}", data.Key);
        }
        private void OnNotification(object sender, EventArgs e)
        {
           // var fabricClient = new FabricClient();
           // fabricClient.ServiceManager.GetServiceDescriptionAsync(new Uri("")).Result.
           //  fabricClient.QueryManager.GetServiceListAsync(new Uri(""),new Uri("")).Result.First().
            var castedEventArgs = (FabricClient.ServiceManagementClient.ServiceNotificationEventArgs)e;

            logger.LogInformation("ServiceNotificationEventArgs was triggered for {@notification}",castedEventArgs.Notification);

           // fabricClient.QueryManager.getin(new Uri("")).Result.First().

            var notification = castedEventArgs.Notification;
            //castedEventArgs.Notification.Endpoints.First();

            GatewayManagementServiceClient.TimeOutRetry.ExecuteAsync(async () =>
            {

                var gateways = await GetGatewayServicesAsync(CancellationToken.None);
                var filtered = gateways.Where(p => p.ServiceName == notification.ServiceName);
                var proxies = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, GatewayServiceRegistrationData>>(STATE_PROXY_DATA_NAME);

                foreach (var data in filtered)
                {
                    var endpoints = notification.Endpoints.SelectMany(en => JToken.Parse(en.Address).ToObject<EndpointsModel>().Endpoints.Values).ToArray();

                    logger.LogInformation("Looking for {service} with endpoint {endpoint} in {@endpoints} {@parsedEndpoints}", data.ServiceName, data.BackendPath, notification.Endpoints, endpoints);

                    

                    if (!endpoints.Any(en => en == data.BackendPath))
                    {
                        using (var tx = this.StateManager.CreateTransaction())
                        {
                            logger.LogInformation("Cleaning out {gateway}", $"{data.Key}-{data.IPAddressOrFQDN}");
                            var cleaned = await proxies.TryRemoveAsync(tx, $"{data.Key}-{data.IPAddressOrFQDN}", GatewayManagementServiceClient.TimeoutSpan, CancellationToken.None);
                            if (cleaned.HasValue)
                            {
                                logger.LogInformation("Cleaned out {@gateway}", cleaned.Value);
                                _lastUpdated = DateTimeOffset.UtcNow;
                                await tx.CommitAsync();
                            }
                         


                        }
                    }
                }
            }).Wait();


                //Console.WriteLine(
                //    "[{0}] received notification for service '{1}'",
                //    DateTime.UtcNow,
                //    notification.ServiceName);
        }
        public async Task RequestCertificateAsync(string hostname, SslOptions options, bool force)
        {
            logger.LogInformation("Begin request for {hostname} certificate with {@ssl_options}. Force={force}", hostname, options, force);
            try
            {
                var certs = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, CertGenerationState>>(STATE_CERTS_DATA_NAME);

                await GatewayManagementServiceClient.TimeOutRetry.ExecuteAsync(async () =>
                {
                    using (var tx = this.StateManager.CreateTransaction())
                    {
                        await certs.AddOrUpdateAsync(tx, hostname,
                            new CertGenerationState { HostName = hostname, SslOptions = options, },
                          (key, old) => new CertGenerationState(!force && old.Completed) { HostName = hostname, SslOptions = options }, GatewayManagementServiceClient.TimeoutSpan, CancellationToken.None);
                        await tx.CommitAsync();
                    }
                });

                var queue = await this.StateManager.GetOrAddAsync<IReliableQueue<string>>(STATE_CERTS_QUEUE_DATA_NAME);

                await GatewayManagementServiceClient.TimeOutRetry.ExecuteAsync(async () =>
                {
                    using (var tx = this.StateManager.CreateTransaction())
                    {
                        await queue.EnqueueAsync(tx, hostname, GatewayManagementServiceClient.TimeoutSpan, CancellationToken.None);

                        await tx.CommitAsync();
                    }
                });
            }
            catch (Exception ex)
            {
                logger.LogInformation(ex, "Throwing in request for {hostname} certificate", hostname);
                throw;
            }
            finally
            {
                logger.LogInformation("End request for {hostname} certificate", hostname);
            }
        }

        public async Task<CertGenerationState> GetCertGenerationInfoAsync(string hostname, CancellationToken token)
        {

            using (logger.BeginEnd("{hostname}", new[] { hostname }))
            {
                try
                {
                    var certs = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, CertGenerationState>>(STATE_CERTS_DATA_NAME);

                    using (var tx = this.StateManager.CreateTransaction())
                    {
                        var result = await certs.TryGetValueAsync(tx, hostname);
                        if (result.HasValue)
                            return result.Value;
                    }

                    return null;
                }
                catch (Exception ex)
                {
                    logger.Throwing(ex);
                    throw;
                }
            }
        }

        public async Task<GatewayServiceRegistrationData[]> GetGatewayServicesAsync(CancellationToken cancellationToken)
        {
            var proxies = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, GatewayServiceRegistrationData>>(STATE_PROXY_DATA_NAME);
            var list = new List<GatewayServiceRegistrationData>();
            using (var tx = this.StateManager.CreateTransaction())
            {
                var enumerable = await proxies.CreateEnumerableAsync(tx);

                using (var e = enumerable.GetAsyncEnumerator())
                {
                    while (await e.MoveNextAsync(cancellationToken).ConfigureAwait(false))
                    {
                        //Remove when upgrade cycle is done
                        if (e.Current.Value.Key.EndsWith(e.Current.Value.IPAddressOrFQDN))
                            e.Current.Value.Key = e.Current.Value.Key.Substring(0, e.Current.Value.Key.Length - 1 - e.Current.Value.IPAddressOrFQDN.Length);

                        list.Add(e.Current.Value);
                    }
                }
            }

            return list.ToArray();
        }
        public async Task<CertGenerationState[]> GetGatewayCertificatesAsync(CancellationToken cancellationToken)
        {
            var proxies = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, CertGenerationState>>(STATE_CERTS_DATA_NAME);
            var list = new List<CertGenerationState>();
            using (var tx = this.StateManager.CreateTransaction())
            {
                var enumerable = await proxies.CreateEnumerableAsync(tx);

                using (var e = enumerable.GetAsyncEnumerator())
                {
                    while (await e.MoveNextAsync(cancellationToken).ConfigureAwait(false))
                    {

                        list.Add(e.Current.Value);
                    }
                }
            }

            return list.ToArray();
        }
        private DateTimeOffset _lastUpdated = DateTimeOffset.MinValue;
        public Task<DateTimeOffset> GetLastUpdatedAsync(CancellationToken token)
        {
            return Task.FromResult(_lastUpdated);
            //var lastupdated = DateTimeOffset.MinValue;

            //var certs = await GetGatewayCertificatesAsync(token);
            //var proxies = await GetGatewayServicesAsync(token);

            //var a= certs.Select(c => c.RunAt.GetValueOrDefault()).Concat(proxies.Select(p => p.Time)).DefaultIfEmpty().Max();
            //return a > _lastUpdated ? a : _lastUpdated;

        }

        public async Task<string> GetChallengeResponseAsync(string hostname, CancellationToken requestAborted)
        {
            var certs = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, CertGenerationState>>(STATE_CERTS_DATA_NAME);

            using (var tx = this.StateManager.CreateTransaction())
            {
                var resutlt = await certs.TryGetValueAsync(tx, hostname, TimeSpan.FromMinutes(1), requestAborted);
                if (resutlt.HasValue)
                {
                    while (resutlt.Value.HttpChallengeInfo == null)
                    {
                        await Task.Delay(2000);
                        resutlt = await certs.TryGetValueAsync(tx, hostname, TimeSpan.FromMinutes(1), requestAborted);

                    }

                    return resutlt.Value.HttpChallengeInfo.KeyAuthString;
                }
            }




            throw new KeyNotFoundException();
        }

        public async Task<string> GetZoneIdAsync(string dnsIdentifier)
        {
            return await GetValue<string, string>(dnsIdentifier, "ZoneIds");
        }

        public async Task UpdateZoneIdAsync(string topLevelDomain, string zoneid)
        {
            await SetValue(topLevelDomain, zoneid, "ZoneIds");

        }

        public async Task<string> GetRemoteLocationAsync(string topLevelDomain)
        {

            return await GetValue<string, string>(topLevelDomain, "Orders");
        }

        private async Task<Value> GetValue<Key, Value>(Key topLevelDomain, string dictKey) where Key : IEquatable<Key>, IComparable<Key>
        {
            var collection = await this.StateManager.GetOrAddAsync<IReliableDictionary<Key, Value>>(dictKey);
            using (var tx = this.StateManager.CreateTransaction())
            {
                var result = await collection.TryGetValueAsync(tx, topLevelDomain, GatewayManagementServiceClient.TimeoutSpan, CancellationToken.None);
                if (result.HasValue)
                    return result.Value;

                await tx.CommitAsync();
            }

            return default(Value);
        }

        private async Task SetValue<Key, Value>(Key topLevelDomain, Value location, string dictKey) where Key : IEquatable<Key>, IComparable<Key>
        {
            var connection = await this.StateManager.GetOrAddAsync<IReliableDictionary<Key, Value>>(dictKey);
            using (var tx = this.StateManager.CreateTransaction())
            {
                await connection.AddOrUpdateAsync(tx, topLevelDomain, location, (a, b) => location, GatewayManagementServiceClient.TimeoutSpan, CancellationToken.None);
                await tx.CommitAsync();
            }
        }

        private async Task<bool> Exists<Key, Value>(Key key, string dictKey) where Key : IEquatable<Key>, IComparable<Key>
        {
            var collection = await this.StateManager.GetOrAddAsync<IReliableDictionary<Key, Value>>(dictKey);
            using (var tx = this.StateManager.CreateTransaction())
            {
                return await collection.ContainsKeyAsync(tx, key, GatewayManagementServiceClient.TimeoutSpan, CancellationToken.None);

            }
        }

        public async Task ClearOrderAsync(string topLevelDomain)
        {
            var orders = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, string>>("Orders");
            using (var tx = this.StateManager.CreateTransaction())
            {
                var result = await orders.TryRemoveAsync(tx, topLevelDomain, GatewayManagementServiceClient.TimeoutSpan, CancellationToken.None);


                await tx.CommitAsync();
            }
        }

        public async Task SetRemoteLocationAsync(string topLevelDomain, string location)
        {

            await SetValue(topLevelDomain, location, "Orders");
        }



        public Task<bool> ExistsAsync(string dnsIdentifier)
        {
            return Exists<string, string>(dnsIdentifier, "Signers");
        }

        public Task<string> GetSignerAsync(string dnsIdentifier)
        {
            return GetValue<string, string>(dnsIdentifier, "Signers");

        }

        public Task SetSigner(string dnsIdentifier, string pem)
        {
            return SetValue<string, string>(dnsIdentifier, pem, "Signers");
        }
    }

    public static class MaxOrDefaultEx
    {

    }


    //    /// <remarks>
    //    /// This class represents an actor.
    //    /// Every ActorID maps to an instance of this class.
    //    /// The StatePersistence attribute determines persistence and replication of actor state:
    //    ///  - Persisted: State is written to disk and replicated.
    //    ///  - Volatile: State is kept in memory only and replicated.
    //    ///  - None: State is kept in memory only and not replicated.
    //    /// </remarks>
    //    [StatePersistence(StatePersistence.Persisted)]
    //[ActorService()]
    //public class GatewayServiceManagerActor : Actor, IGatewayServiceManagerActor, IRemindable
    //{
    //    private const string CREAT_SSL_REMINDERNAME = "processSslQueue";
    //    private const string CERT_QUEUE_NAME = "certQueue";
    //    public const string STATE_LAST_UPDATED_NAME = "lastUpdated";
    //    public const string STATE_PROXY_DATA_NAME = "proxyData";

    //    private readonly StorageConfiguration Storage;
    //    private readonly LetsEncryptService<AcmeContext> letsEncrypt;
    //    private readonly CloudFlareZoneService cloudFlareZoneService;

    //    private CloudStorageAccount StorageAccount;

    //    public GatewayServiceManagerActor(
    //        ActorService actorService,
    //        ActorId actorId,
    //        StorageConfiguration storage,
    //        CloudFlareZoneService cloudFlareZoneService,
    //        LetsEncryptService<AcmeContext> letsEncrypt)
    //        : base(actorService, actorId)
    //    {
    //        this.cloudFlareZoneService = cloudFlareZoneService;
    //        Storage = storage;
    //        this.letsEncrypt = letsEncrypt;
    //    }



    //    public Task<List<GatewayServiceRegistrationData>> GetGatewayServicesAsync() => StateManager.GetStateAsync<List<GatewayServiceRegistrationData>>(STATE_PROXY_DATA_NAME);


    //    public async Task RequestCertificateAsync(string hostname, SslOptions options)
    //    {


    //        await StateManager.AddOrUpdateStateAsync($"cert_{hostname}",
    //            new CertGenerationState { HostName = hostname, SslOptions = options, RunAt = DateTimeOffset.UtcNow },
    //            (key, old) => new CertGenerationState { HostName = hostname, SslOptions = options, RunAt = DateTimeOffset.UtcNow, Completed = old.Completed });

    //        await AddHostnameToQueue(hostname);

    //        await RegisterReminderAsync(CREAT_SSL_REMINDERNAME, new byte[0],
    //           TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(-1));

    //    }

    //    public async Task SetupStorageServiceAsync(int instanceCount)
    //    {
    //        var client = new FabricClient();
    //        var codeContext = this.ActorService.Context.CodePackageActivationContext;

    //        var applicationName = new Uri(codeContext.ApplicationName.StartsWith("fabric:/") ? codeContext.ApplicationName : $"fabric:/{codeContext.ApplicationName}");

    //        var services = await client.QueryManager.GetServiceListAsync(applicationName);

    //        if (!services.Any(s => s.ServiceTypeName == "ApplicationStorageServiceType"))
    //        {

    //            await client.ServiceManager.CreateServiceAsync(new StatelessServiceDescription
    //            {
    //                ServiceTypeName = "ApplicationStorageServiceType",
    //                ApplicationName = applicationName,
    //                ServiceName = new Uri(applicationName.ToString() + "/ApplicationStorageService"),
    //                InstanceCount = instanceCount,
    //                PartitionSchemeDescription = new SingletonPartitionSchemeDescription()
    //            });

    //        }
    //    }
    //    public static AcmeClient client = new AcmeClient(WellKnownServers.LetsEncryptV2);
    //    public static ConcurrentDictionary<string, Task<AcmeAccount>> _acmeaccounts = new ConcurrentDictionary<string, Task<AcmeAccount>>();

    //    public async Task ReceiveReminderAsync(string reminderName, byte[] context, TimeSpan dueTime, TimeSpan period)
    //    {
    //        if (reminderName.Equals(CREAT_SSL_REMINDERNAME))
    //        {

    //            var certs = StorageAccount.CreateCloudBlobClient().GetContainerReference("certs");
    //            await certs.CreateIfNotExistsAsync();



    //            var store = new Queue<string>(await StateManager.GetStateAsync<List<string>>(CERT_QUEUE_NAME).ConfigureAwait(false));
    //            var hostname = store.Dequeue();

    //            var certBlob = certs.GetBlockBlobReference($"{hostname}.crt");
    //            var fullchain = certs.GetBlockBlobReference($"{hostname}.fullchain.pem");
    //            var keyBlob = certs.GetBlockBlobReference($"{hostname}.key");


    //            var certInfo = await StateManager.GetStateAsync<CertGenerationState>($"cert_{hostname}");

    //            if ((await Task.WhenAll(certBlob.ExistsAsync(), keyBlob.ExistsAsync(), fullchain.ExistsAsync())).Any(t => t == false) ||
    //                    await CertExpiredAsync(certBlob))
    //            {

    //                if (certInfo.SslOptions.UseHttp01Challenge)
    //                {
    //                    await HandleHttpChallengeAsync(store, hostname, certBlob, fullchain, keyBlob, certInfo);

    //                }
    //                else
    //                {
    //                    await HandleDnsChallengeAsync(certs, hostname, certBlob, fullchain, keyBlob, certInfo);
    //                }
    //            }
    //            else
    //            {
    //                certInfo.Completed = true;
    //            }


    //            await StateManager.SetStateAsync($"cert_{hostname}", certInfo);


    //            var missing = store.ToList();
    //            await StateManager.SetStateAsync(CERT_QUEUE_NAME, missing);
    //            if (missing.Any())
    //            {
    //                await RegisterReminderAsync(
    //                  CREAT_SSL_REMINDERNAME, new byte[0],
    //                  TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(-1));
    //            }

    //            await StateManager.SetStateAsync(STATE_LAST_UPDATED_NAME, DateTimeOffset.UtcNow);
    //        }

    //    }

    //    private async Task HandleDnsChallengeAsync(CloudBlobContainer certs, string hostname, CloudBlockBlob certBlob, CloudBlockBlob fullchain, CloudBlockBlob keyBlob, CertGenerationState certInfo)
    //    {
    //        try
    //        {

    //            var cert = await letsEncrypt.GenerateCertPairAsync(new GenerateCertificateRequestOptions
    //            {
    //                DnsIdentifier = certInfo.HostName,
    //                SignerEmail = certInfo.SslOptions.SignerEmail,
    //                PfxPassword = ""
    //            });

    //            await keyBlob.UploadFromByteArrayAsync(cert.Item1, 0, cert.Item1.Length);
    //            await certBlob.UploadFromByteArrayAsync(cert.Item2, 0, cert.Item2.Length);
    //            await fullchain.UploadFromByteArrayAsync(cert.Item3, 0, cert.Item3.Length);

    //            certInfo.Completed = true;
    //        }
    //        catch (Exception ex)
    //        {
    //            await certs.GetBlockBlobReference($"{hostname}.err").UploadTextAsync(ex.ToString());

    //        }
    //    }


    //    private async Task HandleHttpChallengeAsync(Queue<string> store, string hostname, CloudBlockBlob certBlob, CloudBlockBlob fullchain, CloudBlockBlob keyBlob, CertGenerationState certInfo)
    //    {
    //        if (certInfo.HttpChallengeInfo == null)
    //        {
    //            try
    //            {
    //                //using (var client = new AcmeClient(WellKnownServers.LetsEncryptStaging))
    //                {

    //                    var account = await _acmeaccounts.AddOrUpdate(certInfo.SslOptions.SignerEmail, AcmeAccountFactory, (email, old) =>
    //                    {
    //                        if (old.IsFaulted || old.IsCanceled)
    //                            return AcmeAccountFactory(email);
    //                        return old;
    //                    });
    //                    // Initialize authorization
    //                    var authz = await client.NewAuthorization(new AuthorizationIdentifier
    //                    {
    //                        Type = AuthorizationIdentifierTypes.Dns,
    //                        Value = hostname
    //                    });
    //                    var httpChallengeInfo = authz.Data.Challenges.First(c => c.Type == ChallengeTypes.Http01);

    //                    certInfo.HttpChallengeInfo = new CertHttpChallengeInfo
    //                    {
    //                        Token = httpChallengeInfo.Token,
    //                        KeyAuthString = client.ComputeKeyAuthorization(httpChallengeInfo),

    //                    };

    //                    await StateManager.SetStateAsync($"cert_{hostname}", certInfo);

    //                    certInfo.HttpChallengeInfo.Location = (await client.CompleteChallenge(httpChallengeInfo)).Location.AbsoluteUri;

    //                    store.Enqueue(hostname);




    //                }
    //            }
    //            catch (Exception ex)
    //            {

    //            }
    //        }
    //        else
    //        {
    //            // using (var client = new AcmeClient(WellKnownServers.LetsEncryptStaging))
    //            {
    //                await Task.Delay(2000);

    //                var location = new Uri(certInfo.HttpChallengeInfo.Location);
    //                // Check authorization status (use the proper challenge to check Authorization State)
    //                var authz = await client.GetAuthorization(location); // or dnsChallenge.Location
    //                if (authz.Data.Status != EntityStatus.Pending)
    //                {

    //                    if (authz.Data.Status == EntityStatus.Valid)
    //                    {
    //                        try
    //                        {
    //                            // Create certificate
    //                            var csr = new CertificationRequestBuilder();
    //                            csr.AddName("CN", hostname);
    //                            var cert = await client.NewCertificate(csr);
    //                            var keyInfo = cert.Key;

    //                            var ms = new MemoryStream();
    //                            keyInfo.Save(ms);

    //                            //  cert.Issuer.Raw 

    //                            //  var keyPair = cert.Key.CreateKeyPair();

    //                            //   var pro = new AsymmetricKeyEntry()//
    //                            // Export Pfx
    //                            var pfxBuilder = cert.ToPfx();
    //                            var pfx = pfxBuilder.Build(hostname, "abcd1234");

    //                            X509Certificate2 certificate = new X509Certificate2(pfx, "abcd1234", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    //                            String pem = "-----BEGIN CERTIFICATE-----\r\n" + Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks) + "\r\n-----END CERTIFICATE-----";

    //                            //var c= certificate.GetRSAPrivateKey();
    //                            // var test = certificate.PrivateKey;
    //                            // RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)test;
    //                            // MemoryStream memoryStream = new MemoryStream();
    //                            // TextWriter streamWriter = new StreamWriter(memoryStream);
    //                            // PemWriter pemWriter = new PemWriter(streamWriter);
    //                            // AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
    //                            // pemWriter.WriteObject(keyPair.Private);
    //                            // streamWriter.Flush();
    //                            // string output = Encoding.ASCII.GetString(memoryStream.GetBuffer()).Trim();
    //                            // int index_of_footer = output.IndexOf("-----END RSA PRIVATE KEY-----");
    //                            // memoryStream.Close();
    //                            // streamWriter.Close();
    //                            // string PrivKey = output.Substring(0, index_of_footer + 29);

    //                            // await keyBlob.UploadTextAsync(PrivKey);
    //                            // var ms = new MemoryStream();
    //                            // var mss = new StreamWriter(ms);
    //                            // var chain = new PemWriter(mss);
    //                            // chain.WriteObject(certificate);
    //                            // mss.Flush();
    //                            // ms.Flush();
    //                            var chiancert = ms.ToArray();
    //                            await keyBlob.UploadFromByteArrayAsync(chiancert, 0, chiancert.Length);
    //                            //  await fullchain.UploadFromByteArrayAsync(cert.Raw, 0, cert.Raw.Length);
    //                            await fullchain.UploadTextAsync(pem);
    //                            var cr = certificate.Export(X509ContentType.Cert);
    //                            await certBlob.UploadFromByteArrayAsync(cr, 0, cr.Length);

    //                            //  File.WriteAllBytes("./my-free-cert.pfx", pfx);

    //                            // // Revoke certificate
    //                            //  await client.RevokeCertificate(cert);
    //                        }
    //                        catch (Exception ex)
    //                        {

    //                        }
    //                        finally
    //                        {
    //                            certInfo.Completed = true;
    //                        }
    //                    }
    //                    else
    //                    {

    //                    }
    //                }
    //                else
    //                {
    //                    store.Enqueue(hostname);
    //                }
    //            }
    //        }
    //    }

    //    private static  async Task<AcmeAccount> AcmeAccountFactory(string email)
    //    {

    //            // Create new registration
    //            var account1 = await client.NewRegistraton("mailto:" + email);


    //            // Accept terms of services
    //            account1.Data.Agreement = account1.GetTermsOfServiceUri();
    //            account1 = await client.UpdateRegistration(account1);
    //            return account1;

    //    }

    //    private async Task<bool> CertExpiredAsync(CloudBlockBlob certBlob)
    //    {
    //        try
    //        {

    //            var bytes = new byte[certBlob.Properties.Length];
    //            await certBlob.DownloadToByteArrayAsync(bytes, 0);

    //            X509Certificate2 clientCertificate =
    //                 new X509Certificate2(bytes);
    //            return clientCertificate.NotAfter.ToUniversalTime() < DateTime.UtcNow;
    //        }catch(Exception ex)
    //        {
    //            return true;
    //        }
    //    }

    //    public async Task RegisterGatewayServiceAsync(GatewayServiceRegistrationData data)
    //    {

    //        if (data.Properties.ContainsKey("CloudFlareZoneId"))
    //        {
    //            var dnsidentifiers = data.ServerName.Split(' ').Select(d => string.Join(".", d.Split('.').TakeLast(2)).ToLower()).Distinct().ToArray();
    //            if (dnsidentifiers.Length == 1)
    //            {
    //                await cloudFlareZoneService.UpdateZoneIdAsync(dnsidentifiers.First(), data.Properties["CloudFlareZoneId"] as string);
    //            }
    //        }

    //        var proxies = await GetGatewayServicesAsync();

    //        var found = proxies.FirstOrDefault(i => i.Key == data.Key);
    //        if (found == null)
    //        {
    //            proxies.Add(data);
    //        }
    //        else
    //        {
    //            proxies[proxies.IndexOf(found)] = data;
    //        }

    //        await StateManager.SetStateAsync(STATE_PROXY_DATA_NAME, proxies);
    //        await StateManager.SetStateAsync(STATE_LAST_UPDATED_NAME, DateTimeOffset.UtcNow);


    //    }

    //    private async Task AddHostnameToQueue(string hostname)
    //    {
    //        var store = await StateManager.GetOrAddStateAsync(CERT_QUEUE_NAME, new List<string> { }).ConfigureAwait(false);
    //        store.Add(hostname);
    //        await StateManager.SetStateAsync(CERT_QUEUE_NAME, store);
    //    }


    //    protected override async Task OnActivateAsync()
    //    {

    //        StorageAccount = await Storage.GetApplicationStorageAccountAsync();

    //        await this.StateManager.TryAddStateAsync(STATE_PROXY_DATA_NAME, new List<GatewayServiceRegistrationData>());

    //        await base.OnActivateAsync();
    //    }

    //    public async Task SetLastUpdatedNow()
    //    {
    //        await StateManager.SetStateAsync(STATE_LAST_UPDATED_NAME, DateTimeOffset.UtcNow);
    //    }
    //}
}
