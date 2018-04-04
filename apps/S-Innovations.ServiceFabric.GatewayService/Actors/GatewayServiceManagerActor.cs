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

namespace SInnovations.ServiceFabric.GatewayService.Actors
{

    public interface ServiceFabricIRS256SignerStore : IService
    {
        Task<bool> ExistsAsync(string dnsIdentifier);

        Task<string> GetSignerAsync(string dnsIdentifier);
        Task SetSigner(string dnsIdentifier, string cert);
    }
    public interface ServiceFabricIOrdersService :  IService
    {
        Task<string> GetRemoteLocationAsync(string topLevelDomain);
        Task ClearOrderAsync(string topLevelDomain);
        Task SetRemoteLocationAsync(string domain, string location);
    }
    public sealed class GatewayManagementService : StatefulService, 
        IGatewayManagementService , ICloudFlareZoneService, ServiceFabricIOrdersService, ServiceFabricIRS256SignerStore
    {
        public const string STATE_LAST_UPDATED_NAME = "lastUpdated";
        public const string STATE_PROXY_DATA_NAME = "ProxyDictionary";
        public const string STATE_CERTS_DATA_NAME = "CertsDictionary";
        public const string STATE_CERTS_QUEUE_DATA_NAME = "CertsQueue";

      //  private readonly CloudFlareZoneService cloudFlareZoneService;
        private readonly StorageConfiguration storage;
        private readonly LetsEncryptService<AcmeContext> letsEncrypt;

        private CloudStorageAccount StorageAccount { get; set; }

        public GatewayManagementService(
            StatefulServiceContext context,
            StorageConfiguration storage,
            LetsEncryptService<AcmeContext> letsEncrypt)
            : base(context)
        {

            this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
            this.letsEncrypt = letsEncrypt ?? throw new ArgumentNullException(nameof(letsEncrypt));
        }

        protected override IEnumerable<ServiceReplicaListener> CreateServiceReplicaListeners()
        {
            return this.CreateServiceRemotingReplicaListeners();
        }

        protected override async Task RunAsync(CancellationToken cancellationToken)
        {
          

            StorageAccount = await storage.GetApplicationStorageAccountAsync();

            var certs = await StateManager.GetOrAddAsync<IReliableDictionary<string, CertGenerationState>>(STATE_CERTS_DATA_NAME);
            var store = await StateManager.GetOrAddAsync<IReliableQueue<string>>(STATE_CERTS_QUEUE_DATA_NAME).ConfigureAwait(false);
            var certContainer = StorageAccount.CreateCloudBlobClient().GetContainerReference("certs");
            await certContainer.CreateIfNotExistsAsync();



            while (!cancellationToken.IsCancellationRequested)
            {
               

                using (var tx = StateManager.CreateTransaction())
                {

                    try
                    {
                        await Test(tx, store, certs, certContainer, cancellationToken);

                        await tx.CommitAsync();
                    }catch(Exception ex)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(60), cancellationToken).ConfigureAwait(false);
                    }
                   
                }
            }
        }
        public async Task Test(ITransaction tx,IReliableQueue<string> store, IReliableDictionary<string, CertGenerationState> certs, CloudBlobContainer certContainer, CancellationToken cancellationToken)
        {

            var itemFromQueue = await store.TryDequeueAsync(tx).ConfigureAwait(false);
            if (!itemFromQueue.HasValue)
            {
                await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);
                return;
            }

            var hostname1 = itemFromQueue.Value;

            //We will assume wildcard certs.

            var domain1 = string.Join(".", hostname1.Split('.').TakeLast(2));


            var certBlob = certContainer.GetBlockBlobReference($"{domain1}.crt");
            var fullchain = certContainer.GetBlockBlobReference($"{domain1}.fullchain.pem");
            var keyBlob = certContainer.GetBlockBlobReference($"{domain1}.key");


            var certInfoLookup = await certs.TryGetValueAsync(tx, hostname1);
            var certInfo = certInfoLookup.Value;



            if (certInfo.Counter < 3 && ((await Task.WhenAll(certBlob.ExistsAsync(), keyBlob.ExistsAsync(), fullchain.ExistsAsync())).Any(t => t == false) ||
                 await CertExpiredAsync(certBlob)))
            {

                if (certInfo.SslOptions.UseHttp01Challenge)
                {
                    await HandleHttpChallengeAsync(store, certs, hostname1, certBlob, fullchain, keyBlob, certInfo);

                }
                else
                {
                    await HandleDnsChallengeAsync(certs, certContainer, hostname1, certBlob, fullchain, keyBlob, certInfo);
                }
            }
            else
            {
                await certs.SetAsync(tx, hostname1, certInfo.Complete());
            }

        }
        public static AcmeClient client = new AcmeClient(WellKnownServers.LetsEncryptV2);
        public static ConcurrentDictionary<string, Task<AcmeAccount>> _acmeaccounts = new ConcurrentDictionary<string, Task<AcmeAccount>>();

        private async Task HandleDnsChallengeAsync(IReliableDictionary<string, CertGenerationState> certs, CloudBlobContainer certsContainer, string hostname, CloudBlockBlob certBlob, CloudBlockBlob fullchain, CloudBlockBlob keyBlob, CertGenerationState certInfo)
        {
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
                    await certs.SetAsync(tx, hostname, certInfo.Complete(),TimeSpan.FromSeconds(10),CancellationToken.None);
                    await tx.CommitAsync();
                }
            }
            catch (Exception ex)
            {
                using (ITransaction tx = StateManager.CreateTransaction())
                {
                    await certs.SetAsync(tx, hostname, certInfo.Increment(), TimeSpan.FromSeconds(10), CancellationToken.None);
                    await tx.CommitAsync();
                }
                await certsContainer.GetBlockBlobReference($"{hostname}.err").UploadTextAsync(ex.ToString());

            }
        }
        private static async Task<AcmeAccount> AcmeAccountFactory(string email)
        {

            // Create new registration
            var account1 = await client.NewRegistraton("mailto:" + email);


            // Accept terms of services
            account1.Data.Agreement = account1.GetTermsOfServiceUri();
            account1 = await client.UpdateRegistration(account1);
            return account1;

        }
        private async Task HandleHttpChallengeAsync( IReliableQueue<string> store, IReliableDictionary<string, CertGenerationState> certs, 
            string hostname, CloudBlockBlob certBlob, CloudBlockBlob fullchain, CloudBlockBlob keyBlob, CertGenerationState certInfo)
        {
            if (certInfo.HttpChallengeInfo == null)
            {
                try
                {
                    //using (var client = new AcmeClient(WellKnownServers.LetsEncryptStaging))
                    {

                        var account = await _acmeaccounts.AddOrUpdate(certInfo.SslOptions.SignerEmail, AcmeAccountFactory, (email, old) =>
                        {
                            if (old.IsFaulted || old.IsCanceled)
                                return AcmeAccountFactory(email);
                            return old;
                        });
                        // Initialize authorization
                        var authz = await client.NewAuthorization(new AuthorizationIdentifier
                        {
                            Type = AuthorizationIdentifierTypes.Dns,
                            Value = hostname
                        });
                        var httpChallengeInfo = authz.Data.Challenges.First(c => c.Type == ChallengeTypes.Http01);
                          
                        using (ITransaction tx = StateManager.CreateTransaction())
                        {
                            await certs.SetAsync(tx, hostname, certInfo.SetCertHttpChallengeInfo(new CertHttpChallengeInfo
                            {
                                Token = httpChallengeInfo.Token,
                                KeyAuthString = client.ComputeKeyAuthorization(httpChallengeInfo),

                            }));

                            await tx.CommitAsync();
                        }
                         
                        using (ITransaction tx = StateManager.CreateTransaction())
                        {
                            await certs.SetAsync(tx, hostname, certInfo.SetCertHttpChallengeLocation((await client.CompleteChallenge(httpChallengeInfo)).Location.AbsoluteUri));
                            await store.EnqueueAsync(tx,hostname);
                            await tx.CommitAsync();
                        }



                    }
                }
                catch (Exception ex)
                {

                }
            }
            else
            {
                // using (var client = new AcmeClient(WellKnownServers.LetsEncryptStaging))
                {
                    await Task.Delay(2000);

                    var location = new Uri(certInfo.HttpChallengeInfo.Location);
                    // Check authorization status (use the proper challenge to check Authorization State)
                    var authz = await client.GetAuthorization(location); // or dnsChallenge.Location
                    if (authz.Data.Status != EntityStatus.Pending)
                    {

                        if (authz.Data.Status == EntityStatus.Valid)
                        {
                            try
                            {
                                // Create certificate
                                var csr = new CertificationRequestBuilder();
                                csr.AddName("CN", hostname);
                                var cert = await client.NewCertificate(csr);
                                var keyInfo = cert.Key;

                                var ms = new MemoryStream();
                                keyInfo.Save(ms);

                                //  cert.Issuer.Raw 

                                //  var keyPair = cert.Key.CreateKeyPair();

                                //   var pro = new AsymmetricKeyEntry()//
                                // Export Pfx
                                var pfxBuilder = cert.ToPfx();
                                var pfx = pfxBuilder.Build(hostname, "abcd1234");

                                X509Certificate2 certificate = new X509Certificate2(pfx, "abcd1234", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                                String pem = "-----BEGIN CERTIFICATE-----\r\n" + Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks) + "\r\n-----END CERTIFICATE-----";

                                //var c= certificate.GetRSAPrivateKey();
                                // var test = certificate.PrivateKey;
                                // RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)test;
                                // MemoryStream memoryStream = new MemoryStream();
                                // TextWriter streamWriter = new StreamWriter(memoryStream);
                                // PemWriter pemWriter = new PemWriter(streamWriter);
                                // AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
                                // pemWriter.WriteObject(keyPair.Private);
                                // streamWriter.Flush();
                                // string output = Encoding.ASCII.GetString(memoryStream.GetBuffer()).Trim();
                                // int index_of_footer = output.IndexOf("-----END RSA PRIVATE KEY-----");
                                // memoryStream.Close();
                                // streamWriter.Close();
                                // string PrivKey = output.Substring(0, index_of_footer + 29);

                                // await keyBlob.UploadTextAsync(PrivKey);
                                // var ms = new MemoryStream();
                                // var mss = new StreamWriter(ms);
                                // var chain = new PemWriter(mss);
                                // chain.WriteObject(certificate);
                                // mss.Flush();
                                // ms.Flush();
                                var chiancert = ms.ToArray();
                                await keyBlob.UploadFromByteArrayAsync(chiancert, 0, chiancert.Length);
                                //  await fullchain.UploadFromByteArrayAsync(cert.Raw, 0, cert.Raw.Length);
                                await fullchain.UploadTextAsync(pem);
                                var cr = certificate.Export(X509ContentType.Cert);
                                await certBlob.UploadFromByteArrayAsync(cr, 0, cr.Length);

                                //  File.WriteAllBytes("./my-free-cert.pfx", pfx);

                                // // Revoke certificate
                                //  await client.RevokeCertificate(cert);
                            }
                            catch (Exception ex)
                            {

                            }
                            finally
                            {
                                
                                using (ITransaction tx = StateManager.CreateTransaction())
                                {
                                    await certs.SetAsync(tx,hostname,certInfo.Complete());
                                    await tx.CommitAsync();
                                }
                            }
                        }
                        else
                        {

                        }
                    }
                    else
                    {
                        using (ITransaction tx = StateManager.CreateTransaction())
                        {
                             await store.EnqueueAsync(tx, hostname);
                            await tx.CommitAsync();
                        }
                    }
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
        }
 

        public async Task RegisterGatewayServiceAsync(GatewayServiceRegistrationData data)
        {
            try
            {
                if (data.Properties.ContainsKey("CloudFlareZoneId"))
                {
                    var dnsidentifiers = data.ServerName.Split(' ').Select(d => string.Join(".", d.Split('.').TakeLast(2)).ToLower()).Distinct().ToArray();
                    if (dnsidentifiers.Length == 1)
                    {
                        await UpdateZoneIdAsync(dnsidentifiers.First(), data.Properties["CloudFlareZoneId"] as string);
                    }
                }

                var proxies = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, GatewayServiceRegistrationData>>(STATE_PROXY_DATA_NAME);


                using (var tx = this.StateManager.CreateTransaction())
                {
                    await proxies.AddOrUpdateAsync(tx, data.Key, data, (key, old) => data);

                    await tx.CommitAsync();


                }
            }catch(Exception ex)
            {
                throw;
            }

        }

        public async Task RequestCertificateAsync(string hostname, SslOptions options, bool force)
        {

            var certs = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, CertGenerationState>>(STATE_CERTS_DATA_NAME);
            
            using (var tx = this.StateManager.CreateTransaction())
            {
                await certs.AddOrUpdateAsync(tx, hostname,
                    new CertGenerationState { HostName = hostname, SslOptions = options, },
                  (key, old) => new CertGenerationState(!force && old.Completed) { HostName = hostname, SslOptions = options }, TimeSpan.FromSeconds(10), CancellationToken.None);
                await tx.CommitAsync();
            }

            var queue = await this.StateManager.GetOrAddAsync<IReliableQueue<string>>(STATE_CERTS_QUEUE_DATA_NAME);

            using (var tx = this.StateManager.CreateTransaction())
            {
                await queue.EnqueueAsync(tx, hostname,TimeSpan.FromSeconds(10),CancellationToken.None);

                await tx.CommitAsync();
            } 
        
        }

        public async Task<CertGenerationState> GetCertGenerationInfoAsync(string hostname, CancellationToken token)
        {
            var certs = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, CertGenerationState>>(STATE_CERTS_DATA_NAME);

            using (var tx = this.StateManager.CreateTransaction())
            {
                var result=await certs.TryGetValueAsync(tx, hostname);
                if(result.HasValue)
                return result.Value;
            }

            return null;
        }

        public async Task<GatewayServiceRegistrationData[]> GetGatewayServicesAsync(CancellationToken cancellationToken)
        {
            var proxies = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, GatewayServiceRegistrationData>>(STATE_PROXY_DATA_NAME);
            var list = new List<GatewayServiceRegistrationData>();
            using (var tx = this.StateManager.CreateTransaction())
            {
                var enumerable = await proxies.CreateEnumerableAsync(tx);

                using(var e = enumerable.GetAsyncEnumerator())
                {
                    while (await e.MoveNextAsync(cancellationToken).ConfigureAwait(false))
                    {
                      
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

        public async Task<DateTimeOffset?> GetLastUpdatedAsync(CancellationToken token)
        {
            var lastupdated = DateTimeOffset.MinValue;

            var certs = await GetGatewayCertificatesAsync(token);
            var proxies = await GetGatewayServicesAsync(token);

            return certs.Select(c => c.RunAt.GetValueOrDefault()).Concat(proxies.Select(p => p.Time)).DefaultIfEmpty().Max();
 
        }

        public async Task<string> GetChallengeResponseAsync(string hostname, CancellationToken requestAborted)
        {
            var certs = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, CertGenerationState>>(STATE_CERTS_DATA_NAME);

            using (var tx = this.StateManager.CreateTransaction())
            {
                var resutlt = await certs.TryGetValueAsync(tx, hostname,TimeSpan.FromMinutes(1), requestAborted);
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
           
            return await GetValue<string,string>(topLevelDomain, "Orders");
        }

        private async Task<Value> GetValue<Key, Value>(Key topLevelDomain, string dictKey) where Key : IEquatable<Key>, IComparable<Key>
        {
            var collection = await this.StateManager.GetOrAddAsync<IReliableDictionary<Key, Value>>(dictKey);
            using (var tx = this.StateManager.CreateTransaction())
            {
                var result = await collection.TryGetValueAsync(tx, topLevelDomain, TimeSpan.FromSeconds(10), CancellationToken.None);
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
                await connection.AddOrUpdateAsync(tx, topLevelDomain, location, (a, b) => location, TimeSpan.FromSeconds(10), CancellationToken.None);
                await tx.CommitAsync();
            }
        }

        private async Task<bool> Exists<Key, Value>(Key key,string dictKey) where Key : IEquatable<Key>, IComparable<Key>
        {
            var collection = await this.StateManager.GetOrAddAsync<IReliableDictionary<Key, Value>>(dictKey);
            using (var tx = this.StateManager.CreateTransaction())
            {
                return await collection.ContainsKeyAsync(tx,key,TimeSpan.FromSeconds(10),CancellationToken.None);
               
            }
        }

        public async Task ClearOrderAsync(string topLevelDomain)
        {
            var orders = await this.StateManager.GetOrAddAsync<IReliableDictionary<string, string>>("Orders");
            using (var tx = this.StateManager.CreateTransaction())
            {
                var result = await orders.TryRemoveAsync(tx, topLevelDomain, TimeSpan.FromSeconds(10), CancellationToken.None);
                

                await tx.CommitAsync();
            }
        }

        public async Task SetRemoteLocationAsync(string topLevelDomain, string location)
        {
            
            await SetValue(topLevelDomain, location, "Orders");
        }

      

        public Task<bool> ExistsAsync(string dnsIdentifier)
        {
            return Exists<string,string>(dnsIdentifier, "Signers");
        }

        public Task<string> GetSignerAsync(string dnsIdentifier)
        {
            return GetValue<string, string>(dnsIdentifier, "Signers");
          
        }

        public Task SetSigner(string dnsIdentifier, string pem)
        {
            return SetValue<string, string>(dnsIdentifier, pem,"Signers");
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
