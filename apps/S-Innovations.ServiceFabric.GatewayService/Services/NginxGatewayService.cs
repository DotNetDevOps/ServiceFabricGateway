using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.ServiceFabric.Services.Client;
using Microsoft.ServiceFabric.Services.Remoting.Client;
using Microsoft.ServiceFabric.Services.Remoting.V2.FabricTransport.Client;
using Microsoft.WindowsAzure.Storage;
using Newtonsoft.Json;
using Polly;
using Polly.Retry;
using SInnovations.ServiceFabric.Gateway.Actors;
using SInnovations.ServiceFabric.Gateway.Common.Model;
using SInnovations.ServiceFabric.Gateway.Model;
using SInnovations.ServiceFabric.GatewayService.Configuration;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Model;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Services;
using SInnovations.ServiceFabric.Storage.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Fabric;
using System.Fabric.Description;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Unity;
using SInnovations.ServiceFabric.Gateway.Common.Extensions;

namespace SInnovations.ServiceFabric.GatewayService.Services
{
    /// <summary>
    /// A specialized stateless service for hosting ASP.NET Core web apps.
    /// </summary>
    public sealed class NginxGatewayService : KestrelHostingService<Startup>
    {
        private const string nginxVersion = "nginx-1.11.13.exe";
        private string nginxProcessName = "";

        private readonly StorageConfiguration Storage;
        private CloudStorageAccount storageAccount;
        private readonly ILogger _logger;

        private readonly FabricClient _fabricClient = new FabricClient();

        public NginxGatewayService(StatelessServiceContext serviceContext,
            IUnityContainer container, ILoggerFactory factory,
            StorageConfiguration storage,
            ConfigurationPackage configurationPackage)
            : base(new KestrelHostingServiceOptions
            {
                 GatewayOptions = new GatewayOptions
                {
                    Key = "NGINX-MANAGER",
                    ReverseProxyLocation = configurationPackage.Settings.Sections["Gateway"].Parameters["ReverseProxyLocation"].Value,
                    ServerName =  configurationPackage.Settings.Sections["Gateway"].Parameters["ServerName"].Value,
                    Ssl = JsonConvert.DeserializeObject<SslOptions>(configurationPackage.Settings.Sections["Gateway"].Parameters["SslOptions"].Value),
                    Properties = JsonConvert.DeserializeObject<Dictionary<string,object>>(configurationPackage.Settings.Sections["Gateway"].Parameters["Properties"].Value)
                 },
                //AdditionalGateways = new GatewayOptions[]
                //{
                //    new GatewayOptions
                //    {
                //       Key ="NGINX-MANAGER-LOCAL",
                //       ReverseProxyLocation = "/manage/",
                //       ServerName = "local.earthml.com",
                //       Ssl = new SslOptions
                //       {
                //            Enabled = true,
                //            SignerEmail = "info@earthml.com",
                //       //     UseHttp01Challenge = true
                //       },
                //        Properties = new Dictionary<string, object> { {"CloudFlareZoneId", "ac1d153353eebc8508f7bb31ef1ab46c" } }
                //    }
                //}

            }, serviceContext, factory, container)
        {
            Storage = storage;
            _logger = factory.CreateLogger<NginxGatewayService>();
        }

        #region StatelessService


        protected override void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton(this);
            base.ConfigureServices(services);
        }

        private bool IsNginxRunning()
        {
            if (!string.IsNullOrEmpty(nginxProcessName))
            {
                var processes = Process.GetProcessesByName(nginxProcessName);
                return processes.Length != 0;
            }
            else
                return false;
        }

        private async Task WriteConfigAsync(CancellationToken token)
        {

            _logger.LogInformation("Writing Nginx Configuration");

            var endpoint = FabricRuntime.GetActivationContext().GetEndpoint("NginxServiceEndpoint");
            var sslEndpoint = FabricRuntime.GetActivationContext().GetEndpoint("NginxSslServiceEndpoint");

         

            var sb = new StringBuilder();

            sb.AppendLine("worker_processes  4;");
            sb.AppendLine("events {\n\tworker_connections  1024;\n}");
            sb.AppendLine("http {");


            sb.AppendLine();

            sb.AppendLine("\tclient_max_body_size 100m;");


            File.WriteAllText("mime.types", WriteMimeTypes(sb, "mime.types").ToString());

            sb.AppendLine("\tkeepalive_timeout          65;");


            /// ******************************  begin gzip section ********************
            /// Compression           
            sb.AppendLine("\tgzip                       on;"); /// # Enable Gzip compressed.

            ///# Enable compression both for HTTP/1.0 and HTTP/1.1.
            sb.AppendLine("\tgzip_http_version  1.1;");


            sb.AppendLine("\tserver_names_hash_bucket_size  128;");

     

            ///Compression level (1-9).
            /// 5 is a perfect compromise between size and cpu usage, offering about
            /// 75% reduction for most ascii files (almost identical to level 9).
            sb.AppendLine("\tgzip_comp_level    5;");

            /// Don't compress anything that's already small and unlikely to shrink much
            ///if at all (the default is 20 bytes, which is bad as that usually leads to
            /// larger files after gzipping).
            sb.AppendLine("\tgzip_min_length    1000;");

            /// Compress data even for clients that are connecting to us via proxies,
            /// identified by the "Via" header (required for CloudFront).
            sb.AppendLine("\tgzip_proxied       any;");

            /// Tell proxies to cache both the gzipped and regular version of a resource
            /// whenever the client's Accept-Encoding capabilities header varies;
            /// Avoids the issue where a non-gzip capable client (which is extremely rare
            /// today) would display gibberish if their proxy gave them the gzipped version.
            sb.AppendLine("\tgzip_vary          on;");

            /// Compress all output labeled with one of the following MIME-types.
            /// text/html is always compressed by HttpGzipModule
            sb.AppendLine("\tgzip_types");
            {
                sb.AppendLine("\t\ttext/css");
                sb.AppendLine("\t\ttext/*");
                sb.AppendLine("\t\ttext/javascript");
                sb.AppendLine("\t\tapplication/javascript");
                sb.AppendLine("\t\tmessage/*");
                sb.AppendLine("\t\tapplication/x-javascript");
                sb.AppendLine("\t\tapplication/json");
                sb.AppendLine("\t\tapplication/xml");
                sb.AppendLine("\t\tapplication/atom+xml");
                sb.AppendLine("\t\tapplication/xaml+xml;");
            }
            ///******************************  end gzip section ********************


            sb.AppendLine("\tproxy_buffer_size          128k;");
            sb.AppendLine("\tproxy_buffers              4 256k;");
            sb.AppendLine("\tproxy_busy_buffers_size    256k;");



            {
                var proxiesAll = await GetGatewayServicesAsync(token);
                var proxies = proxiesAll.Where(p => p.Ready).ToList();

                var codePackage = this.Context.CodePackageActivationContext.CodePackageName;
                var codePath = this.Context.CodePackageActivationContext.GetCodePackageObject(codePackage).Path;




                foreach (var upstreams in proxies.GroupBy(k => k.ServiceName))
                {
                   

                    GatewayServiceRegistrationData[] uniques = GetUniueGatewayRegistrations(upstreams);

                    var upstreamName = upstreams.Key.AbsoluteUri.Split('/').Last().Replace('.', '_');

                    _logger.LogInformation("Writing upstream {upstreamName} for {serviceName}",upstreamName, upstreams.Key);
                
                     
                    sb.AppendLine($"\tupstream {upstreamName} {{");

                    var upstreamIp_Hash = upstreams.Any(u => u.Properties.ContainsKey("upstream_ip_hash") && (bool)u.Properties["upstream_ip_hash"]);
                    if (upstreamIp_Hash)
                    {
                        sb.AppendLine("\t\tip_hash;");
                        _logger.LogInformation("Adding ip_hash to upstream {upstreamName}", upstreamName);
                    }

                    var hasLocalService = uniques.Any(c => c.IPAddressOrFQDN == Context.NodeContext.IPAddressOrFQDN);

                    foreach (var upstream in uniques)
                    {
                        var server = $"\t\tserver {new Uri(upstream.BackendPath).Authority.Replace("localhost", "127.0.0.1")} {(upstream.IPAddressOrFQDN != Context.NodeContext.IPAddressOrFQDN && !upstreamIp_Hash && hasLocalService ? "backup" : "")};";

                        _logger.LogInformation("{upstream} : {server}",upstreamName,server.Trim());
                        sb.AppendLine(server);
                    }
                    sb.AppendLine("\t}");


                    try
                    {
                        if (Directory.Exists(Path.Combine(codePath, $"cache/{upstreamName}")))
                        {
                            Directory.Delete(Path.Combine(codePath, $"cache/{upstreamName}"), true);
                        }
                    }
                    catch (Exception ex)
                    {

                    }

                    sb.AppendLine($"\tproxy_cache_path  cache/{upstreamName}  levels=1:2    keys_zone={upstreamName}:10m inactive=24h  max_size=1g;");


                }

                sb.AppendLine("\tmap $http_upgrade $connection_upgrade {");
                sb.AppendLine("\t\tdefault upgrade;");
                sb.AppendLine("\t\t''      keep-alive;");
                sb.AppendLine("\t}");

                sb.AppendLine("\tserver {");
                sb.AppendLine($"\t\tlisten       {endpoint.Port};");
                sb.AppendLine("\t\tserver_name   everything;");
                sb.AppendLine("\t\tlocation / {");
                sb.AppendLine("\t\t\treturn 444;");
                sb.AppendLine("\t\t}");
                sb.AppendLine("\t\tlocation = /heathcheck {");
                sb.AppendLine("\t\t\treturn 200;");
                sb.AppendLine("\t\t}");
                sb.AppendLine("\t\tlocation /manage/ {");
                sb.AppendLine("\t\t\treturn 200;");
                sb.AppendLine("\t\t}");
                sb.AppendLine("\t}");

                foreach (var serverGroup in proxies.GroupByServerName())
                {
                    var serverName = serverGroup.Key;
                    var sslOn = serverName != "localhost" && serverGroup.Value.Any(k => k.Ssl.Enabled);

                    if (sslOn)
                    {

                        var state = await GetCertGenerationStateAsync(serverName, serverGroup.Value.First().Ssl, false, token);

                        _logger.LogInformation("Certificate for {servername}: IsNull={isNull} IsCompleted={isCompleted}", serverName, state == null, state?.Completed??false);
                        sslOn = state != null && state.Completed;

                        _logger.LogInformation("Certificate for {servername}: IsNull={isNull} IsCompleted={isCompleted} sslOn={sslOn}", serverName, state == null, state?.Completed ?? false,sslOn);
                    }

                    if (serverName.StartsWith("www.") && serverGroup.Value.Any(a => a.Properties.ContainsKey("www301") && (bool)a.Properties["www301"]))
                    {
                        sb.AppendLine("\tserver {");
                        {

                            sb.AppendLine($"\t\tlisten       {endpoint.Port};");
                            if (sslOn)
                            {
                                sb.AppendLine($"\t\tlisten       {sslEndpoint.Port} ssl;");
                            }

                            sb.AppendLine($"\t\tserver_name  {serverName.Substring(4)};");
                            sb.AppendLine($"\t\treturn 301 $scheme://{serverName}$request_uri;");
                            sb.AppendLine();
                        }
                        sb.AppendLine("\t}");
                    }
                    else if (serverGroup.Value.Any(a => a.Properties.ContainsKey("www301") && (bool)a.Properties["www301"]))
                    {
                        sb.AppendLine("\tserver {");
                        {

                            sb.AppendLine($"\t\tlisten       {endpoint.Port};");
                            if (sslOn)
                            {
                                sb.AppendLine($"\t\tlisten       {sslEndpoint.Port} ssl;");
                            }

                            sb.AppendLine($"\t\tserver_name  www.{serverName};");
                            sb.AppendLine($"\t\treturn 301 $scheme://{serverName}$request_uri;");
                            sb.AppendLine();
                        }
                        sb.AppendLine("\t}");
                    }




                    sb.AppendLine("\tserver {");
                    {




                        sb.AppendLine($"\t\tlisten       {endpoint.Port};");

                        var sslsb = new StringBuilder();

                        if (sslOn)
                        {
                            sslsb.AppendLine($"\t\tlisten       {sslEndpoint.Port} ssl;");
                            sslsb.AppendLine($"\t\tserver_name  {serverName};");
                            sslsb.AppendLine();

                            sslOn = await SetupSsl(sslsb, serverGroup.Value.First(), serverName, token);
                        }
                         

                        if(sslOn)
                        {
                            sb.AppendLine(sslsb.ToString());
                        }
                        else
                        {
                            sb.AppendLine($"\t\tserver_name  {serverName};");
                            sb.AppendLine();
                        }

                        var test = new HashSet<string>();

                        foreach (var a in serverGroup.Value)
                        {
                            // if (a.IPAddressOrFQDN == Context.NodeContext.IPAddressOrFQDN)
                            if (!test.Contains(a.ReverseProxyLocation))
                            {
                                var upstreamName = a.ServiceName.AbsoluteUri.Split('/').Last().Replace('.', '_');

                                var url = a.BackendPath;
                                url = "http://" + upstreamName;

                                await WriteProxyPassLocation(2, a.ReverseProxyLocation, url, sb,
                                    $"\"{a.ServiceName.AbsoluteUri.Substring("fabric:/".Length)}/{a.ServiceVersion}\"", upstreamName, a);
                                test.Add(a.ReverseProxyLocation);
                            }
                        }

                        {
                            var upstreamName = this.Context.ServiceName.AbsoluteUri.Split('/').Last().Replace('.', '_');

                            await WriteProxyPassLocation(2,
                                "/.well-known/acme-challenge/", "http://" + upstreamName, sb,
                                $"\"{ this.Context.ServiceName.AbsoluteUri.Substring("fabric:/".Length)}/{ this.Context.CodePackageActivationContext.GetServiceManifestVersion()}\"",
                                upstreamName, null
                                );
                        }


                    }
                    sb.AppendLine("\t}");
                }

            }
            sb.AppendLine("}");

            File.WriteAllText("nginx.conf", sb.ToString());
        }

        private async Task<bool> SetupSsl(StringBuilder sb, GatewayServiceRegistrationData gatewayServiceRegistrationData, string serverName, CancellationToken token)
        {

           
            var certCN =gatewayServiceRegistrationData.Ssl.UseHttp01Challenge ? serverName : string.Join(".", serverName.Split('.').TakeLast(2));

            var certs = storageAccount.CreateCloudBlobClient().GetContainerReference("certs");

            var keyBlob = certs.GetBlockBlobReference($"{certCN}.key");
            var chainBlob = certs.GetBlockBlobReference($"{certCN}.fullchain.pem");

            Directory.CreateDirectory(Path.Combine(Context.CodePackageActivationContext.WorkDirectory, "letsencrypt"));

          

            if (await chainBlob.ExistsAsync() && await keyBlob.ExistsAsync())
            {
                await keyBlob.DownloadToFileAsync($"{Context.CodePackageActivationContext.WorkDirectory}/letsencrypt/{certCN}.key", FileMode.Create);
                await chainBlob.DownloadToFileAsync($"{Context.CodePackageActivationContext.WorkDirectory}/letsencrypt/{certCN}.fullchain.pem", FileMode.Create);

                sb.AppendLine($"\t\tssl_certificate {Context.CodePackageActivationContext.WorkDirectory}/letsencrypt/{certCN}.fullchain.pem;");
                sb.AppendLine($"\t\tssl_certificate_key {Context.CodePackageActivationContext.WorkDirectory}/letsencrypt/{certCN}.key;");

                sb.AppendLine($"\t\tssl_session_timeout  5m;");

                sb.AppendLine($"\t\tssl_prefer_server_ciphers on;");
                sb.AppendLine($"\t\tssl_protocols TLSv1 TLSv1.1 TLSv1.2;");
                sb.AppendLine($"\t\tssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';");
                sb.AppendLine($"\t\tadd_header Strict-Transport-Security max-age=15768000;");


                return true;
            }



            await GetCertGenerationStateAsync(serverName, gatewayServiceRegistrationData.Ssl, true, token);

            return false;
               
             
        }

        private static GatewayServiceRegistrationData[] GetUniueGatewayRegistrations(IGrouping<Uri, GatewayServiceRegistrationData> upstreams)
        {
            var hashset = new HashSet<string>();

            var uniques = upstreams.Where(upstream =>
            {
                var added = hashset.Contains(new Uri(upstream.BackendPath).Authority);
                if (!added) { hashset.Add(new Uri(upstream.BackendPath).Authority); }
                return !added;
            }).ToArray();
            return uniques;
        }

        private static StringBuilder WriteMimeTypes(StringBuilder sb, string name)
        {
            var mime = new StringBuilder();
            sb.AppendLine($"\tinclude {name};");
            sb.AppendLine("\tdefault_type application/octet-stream;");
            mime.AppendLine("types{");
            foreach (var type in Constants.ExtensionMapping.GroupBy(kv => kv.Value, kv => kv.Key))
            {
                mime.AppendLine($"\t{type.Key} {string.Join(" ", type.Select(t => t.Trim('.')))};");
            }
            mime.AppendLine("}");

            return mime;

        }

        public static string ToGuid(string input)
        {
           
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.Default.GetBytes(input));
              return new Guid(hash).ToString("N");
            }
        }

        private static async Task WriteProxyPassLocation(int level, string location, string url, StringBuilder sb_outer, string uniquekey, string upstreamName, GatewayServiceRegistrationData   gatewayServiceRegistrationData)
        {
          
            var tabs = string.Join("", Enumerable.Range(0, level + 1).Select(r => "\t"));

            sb_outer.AppendLine($"{string.Join("", Enumerable.Range(0, level).Select(r => "\t"))}location {location} {{");
            {
                var sb = new StringBuilder();



                // rewrite ^ /268be5f6-90b1-4aa1-9eac-2225d8f7ab29/131356467681395031/$1 break;
                var uri = new Uri(url);
                if (location.StartsWith("~") || location.Trim().StartsWith("/.well-known/"))
                {


                    if (!string.IsNullOrEmpty(uri.AbsolutePath?.TrimEnd('/')))
                    {
                        sb.AppendLine($"{tabs}rewrite ^ {uri.AbsolutePath}$uri break;");
                    }

                    sb.AppendLine($"{tabs}proxy_pass {uri.GetLeftPart(UriPartial.Authority)};");
                }
                else
                {
                    if(gatewayServiceRegistrationData?.Properties.ContainsKey("nginx-rewrite")?? false)
                    {
                        sb.AppendLine($"{tabs}rewrite {gatewayServiceRegistrationData?.Properties["nginx-rewrite"]}");
                    }
                    sb.AppendLine($"{tabs}proxy_pass {url.TrimEnd('/')}/;");



                }


                if (gatewayServiceRegistrationData?.Properties.ContainsKey("cf-real-ip") ?? false)
                {

                    var realIpPath = "conf/realip.conf";
                    Directory.CreateDirectory(Path.GetFullPath("conf"));

                    var realIp = new StringBuilder();

                    var http = new HttpClient();
                    var ipsv4 = await http.GetStringAsync("https://www.cloudflare.com/ips-v4");
                    var ipsv6 = await http.GetStringAsync("https://www.cloudflare.com/ips-v6");
                    var breaks = new[] { "\r\n", "\r", "\n" };
                    foreach (var line in ipsv4
                        .Split(breaks ,   StringSplitOptions.None)
                        .Concat(ipsv6.Split(breaks, StringSplitOptions.None))
                        .Where(s=>!string.IsNullOrWhiteSpace(s)))
                    {
                        realIp.AppendLine($"set_real_ip_from  {line};");
                    }
                    realIp.AppendLine($"real_ip_header  CF-Connecting-IP;");
                    File.WriteAllText(realIpPath, realIp.ToString());
                    sb.AppendLine($"{tabs}include {Path.GetFullPath(realIpPath).Replace("\\","/")};");
                }




                    if (gatewayServiceRegistrationData?.CacheOptions?.Enabled ?? false)
                {
                    sb.AppendLine($"{tabs}proxy_cache {upstreamName};");

                    sb.AppendLine($"{tabs}proxy_cache_revalidate on;");
                    sb.AppendLine($"{tabs}proxy_cache_min_uses 3;");
                    sb.AppendLine($"{tabs}add_header X-Cache-Status $upstream_cache_status;");

                    sb.AppendLine($"{tabs}proxy_cache_valid      200  1d;");
                    sb.AppendLine($"{tabs}proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;");
                }



                //  sb.AppendLine($"{tabs}proxy_redirect off;");
                sb.AppendLine($"{tabs}server_name_in_redirect on;");
                sb.AppendLine($"{tabs}port_in_redirect off;");


                sb.AppendLine($"{tabs}proxy_set_header Upgrade $http_upgrade;");
                sb.AppendLine($"{tabs}proxy_set_header Connection $connection_upgrade;"); 
                //
                sb.AppendLine($"{tabs}proxy_set_header Host					  $host;");
                sb.AppendLine($"{tabs}proxy_set_header X-Real-IP              $remote_addr;");
                sb.AppendLine($"{tabs}proxy_set_header X-Forwarded-For        $proxy_add_x_forwarded_for;");
                sb.AppendLine($"{tabs}proxy_set_header X-Forwarded-Host       $host;");
                sb.AppendLine($"{tabs}proxy_set_header X-Forwarded-Server     $host;");
                sb.AppendLine($"{tabs}proxy_set_header X-Forwarded-Proto      $scheme;");
                sb.AppendLine($"{tabs}proxy_set_header X-Forwarded-Path       $request_uri;");
                sb.AppendLine($"{tabs}proxy_set_header X-ServiceFabric-Key    {uniquekey};");

                sb.AppendLine($"{tabs}proxy_connect_timeout                   3s;");
                sb.AppendLine($"{tabs}proxy_http_version                      1.1;");


                if (location.Trim().StartsWith("~") || location.Trim().StartsWith("/.well-known/"))
                    sb.AppendLine($"{tabs}proxy_set_header X-Forwarded-PathBase   /;");
                else if(location.Trim().StartsWith("="))
                    sb.AppendLine($"{tabs}proxy_set_header X-Forwarded-PathBase   {location.Substring(1).Trim()};");
                else
                {
                    var pathbase = location.TrimEnd('/');
                    sb.AppendLine($"{tabs}proxy_set_header X-Forwarded-PathBase   {(string.IsNullOrEmpty(pathbase) ? "/" : pathbase)};");                  
                }

                sb.AppendLine($"{tabs}proxy_cache_bypass $http_upgrade;");
                sb.AppendLine($"{tabs}proxy_cache_bypass $http_pragma;");


                var path = $"conf/{ToGuid(location + gatewayServiceRegistrationData?.Key)}.conf";
                Directory.CreateDirectory(Path.GetFullPath("conf"));
                File.WriteAllText(path, sb.ToString());

                sb_outer.AppendLine($"{tabs}include {Path.GetFullPath(path).Replace("\\", "/")};");
             //   sb_outer.Append(sb.ToString());
            }
            sb_outer.AppendLine($"{string.Join("", Enumerable.Range(0, level).Select(r => "\t"))}}}");


            if(gatewayServiceRegistrationData?.Properties?.ContainsKey("nginx-locations") ?? false)
            {
                var additionals = (string[])gatewayServiceRegistrationData.Properties["nginx-locations"];
                foreach (var extra in additionals)
                {
                    sb_outer.AppendLine($"{string.Join("", Enumerable.Range(0, level).Select(r => "\t"))}location {extra} {{");
                    {
                        var path = $"conf/{ToGuid(location + gatewayServiceRegistrationData?.Key)}.conf";
                        sb_outer.AppendLine($"{tabs}include {Path.GetFullPath(path)};");
                    }
                    sb_outer.AppendLine($"{string.Join("", Enumerable.Range(0, level).Select(r => "\t"))}}}");

                }
            }

           
        }



        private void LaunchNginxProcess(string arguments)
        {
            var codePackage = this.Context.CodePackageActivationContext.CodePackageName;
            var codePath = this.Context.CodePackageActivationContext.GetCodePackageObject(codePackage).Path;
            var res = File.Exists(Path.Combine(codePath, nginxVersion));
            var nginxStartInfo = new ProcessStartInfo(Path.Combine(codePath, nginxVersion))
            {
                WorkingDirectory = codePath,
                UseShellExecute = false,
                Arguments = arguments
            };
            var nginxProcess = new Process()
            {
                StartInfo = nginxStartInfo
            };
            nginxProcess.Start();
            try
            {
                nginxProcessName = nginxProcess.ProcessName;
            }
            catch (Exception)
            {

            }
        }


        protected override Task OnCloseAsync(CancellationToken cancellationToken)
        {
            if (IsNginxRunning())
                LaunchNginxProcess($"-c \"{Path.GetFullPath("nginx.conf")}\" -s quit");


            return base.OnCloseAsync(cancellationToken);
        }

        protected override async Task OnOpenAsync(CancellationToken cancellationToken)
        {
            await base.OnOpenAsync(cancellationToken);
        }
        protected override void OnAbort()
        {
            if (IsNginxRunning())
                LaunchNginxProcess($"-c \"{Path.GetFullPath("nginx.conf")}\" -s quit");



            base.OnAbort();
        }
        private DateTimeOffset lastWritten = DateTimeOffset.MinValue;


        //public async Task DeleteGatewayServiceAsync(string v, CancellationToken cancellationToken)
        //{
        //    var applicationName = this.Context.CodePackageActivationContext.ApplicationName;
        //    var actorServiceUri = new Uri($"{applicationName}/GatewayServiceManagerActorService");
        //    List<long> partitions = await GetPartitionsAsync(actorServiceUri);
        //    var serviceProxyFactory = new ServiceProxyFactory(c => new FabricTransportServiceRemotingClientFactory());


        //    foreach (var partition in partitions)
        //    {
        //        var actorService = serviceProxyFactory.CreateServiceProxy<IGatewayServiceManagerActorService>(actorServiceUri, new ServicePartitionKey(partition));
        //        await actorService.DeleteGatewayServiceAsync(v, cancellationToken);
        //    }

        //}
        public async Task<List<GatewayServiceRegistrationData>> GetGatewayServicesAsync(CancellationToken cancellationToken)
        {
            var applicationName = this.Context.CodePackageActivationContext.ApplicationName;
            var actorServiceUri = new Uri($"{applicationName}/{nameof(GatewayManagementService)}");
            List<long> partitions = await GetPartitionsAsync(actorServiceUri);

            var serviceProxyFactory = new ServiceProxyFactory(c => new FabricTransportServiceRemotingClientFactory());

            var all = new List<GatewayServiceRegistrationData>();
            foreach (var partition in partitions)
            {
                var actorService = serviceProxyFactory.CreateServiceProxy<IGatewayManagementService>(actorServiceUri, new ServicePartitionKey(partition));

                var state = await actorService.GetGatewayServicesAsync(cancellationToken);
                all.AddRange(state);

            }
            return all;
        }

        private async Task<List<long>> GetPartitionsAsync(Uri actorServiceUri)
        {
            var partitions = new List<long>();
            var servicePartitionList = await _fabricClient.QueryManager.GetPartitionListAsync(actorServiceUri);
            foreach (var servicePartition in servicePartitionList)
            {
                var partitionInformation = servicePartition.PartitionInformation as Int64RangePartitionInformation;
                partitions.Add(partitionInformation.LowKey);
            }

            return partitions;
        }

        public async Task<CertGenerationState> GetCertGenerationStateAsync(string hostname, SslOptions options, bool force, CancellationToken token)
        {
            _logger.LogInformation("Begin GetCertGenerationState {hostname}, Force={force}",hostname,force);

            try
            {
                var gateway = GatewayManagementServiceClient.GetProxy<IGatewayManagementService>(
                    $"{this.Context.CodePackageActivationContext.ApplicationName}/{nameof(GatewayManagementService)}", hostname);
               

                if (!force)
                {

                    var state = await gateway.GetCertGenerationInfoAsync(hostname, token);
                    if (state != null && state.RunAt.HasValue && state.RunAt.Value > DateTimeOffset.UtcNow.Subtract(TimeSpan.FromDays(14)))
                    {
                        return state;
                    }
                }


                _logger.LogInformation("Requesting certificate for {hostname}, Force={force}", hostname, force);

                await gateway.RequestCertificateAsync(hostname, options, force);

            } catch(Exception ex)
            {
                _logger.LogWarning(ex,"Throwing GetCertGenerationState {hostname}", hostname);
                return null;
            }
            finally{

                _logger.LogInformation("End GetCertGenerationState {hostname}", hostname);
            }
            
            // await ActorProxy.Create<IGatewayServiceManagerActor>(new ActorId(hostname))

            //if (options.UseHttp01Challenge)
            //{
            //    var actorService = ActorServiceProxy.Create<IGatewayServiceManagerActorService>(actorServiceUri, new ActorId(hostname));

            //    var state = await actorService.GetCertGenerationInfoAsync(hostname, options, token);
            //    if (state != null && state.RunAt.HasValue && state.RunAt.Value > DateTimeOffset.UtcNow.Subtract(TimeSpan.FromDays(14)))
            //    {
            //        return state;
            //    }

            //    await ActorProxy.Create<IGatewayServiceManagerActor>(new ActorId(hostname)).RequestCertificateAsync(hostname, options);



            //}

            //if (!force)
            //{
            //    {
            //        var proxy =ActorServiceProxy.Create<IGatewayServiceManagerActorService>
            //    }
            //    {
            //        List<long> partitions = await GetPartitionsAsync(actorServiceUri);

            //        var serviceProxyFactory = new ServiceProxyFactory(c => new FabricTransportServiceRemotingClientFactory());

            //        var actors = new Dictionary<long, DateTimeOffset>();
            //        foreach (var partition in partitions)
            //        {
            //            var actorService = serviceProxyFactory.CreateServiceProxy<IGatewayServiceManagerActorService>(actorServiceUri, new ServicePartitionKey(partition));

            //            var state = await actorService.GetCertGenerationInfoAsync(hostname, options, token);
            //            if (state != null && state.RunAt.HasValue && state.RunAt.Value > DateTimeOffset.UtcNow.Subtract(TimeSpan.FromDays(14)))
            //            {
            //                return state;
            //            }

            //        }
            //    }
            //}

            //var gateway = ActorProxy.Create<IGatewayServiceManagerActor>(new ActorId("*"));
            //await gateway.RequestCertificateAsync(hostname, options);

            return null;
        }
        //public async Task SetLastUpdatedAsync(DateTimeOffset time, CancellationToken token)
        //{

        //    var gateway = ActorProxy.Create<IGatewayServiceManagerActor>(new ActorId("*"));
        //    await gateway.SetLastUpdatedNow();

        //}
        public async Task<DateTimeOffset> GetLastUpdatedAsync(CancellationToken token)
        {
            var lastupdated = DateTimeOffset.MinValue;

            var applicationName = this.Context.CodePackageActivationContext.ApplicationName;
            var actorServiceUri = new Uri($"{applicationName}/{nameof(GatewayManagementService)}");
            List<long> partitions = await GetPartitionsAsync(actorServiceUri);

            //var serviceProxyFactory = new ServiceProxyFactory(c => new FabricTransportServiceRemotingClientFactory());

            var updated = await Task.WhenAll(
                partitions.Select(partition => 
                ServiceProxy.Create<IGatewayManagementService>(actorServiceUri, new ServicePartitionKey(partition)).GetLastUpdatedAsync(token)));

            return updated.DefaultIfEmpty().Max(v=>v);
            
           
        }
      
        protected override async Task RunAsync(CancellationToken cancellationToken)
        {
            var applicationName = this.Context.CodePackageActivationContext.ApplicationName;
            var actorServiceUri = new Uri($"{applicationName}/{nameof(GatewayManagementService)}");


            RetryPolicy retryPolicy = Policy
            .Handle<Exception>()            
            .WaitAndRetryAsync(5, retryAttempt =>
              TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)),
            (exception, timeSpan, context) => {
                _logger.LogWarning(exception, "Retrying to write config");
            }
            );

            try
            {

                storageAccount = await Storage.GetApplicationStorageAccountAsync();

                var gateway = ServiceProxy.Create<IGatewayManagementService>(actorServiceUri,  Path.GetRandomFileName().ToPartitionHashFunction());
                var a = await _fabricClient.ServiceManager.GetServiceDescriptionAsync(this.Context.ServiceName) as StatelessServiceDescription;

                await gateway.SetupStorageServiceAsync(a.InstanceCount);

                await retryPolicy.ExecuteAsync(() => WriteConfigAsync(cancellationToken));

                LaunchNginxProcess($"-c \"{Path.GetFullPath("nginx.conf")}\"");



                while (true)
                {
                    if (cancellationToken.IsCancellationRequested)
                        LaunchNginxProcess($"-c \"{Path.GetFullPath("nginx.conf")}\" -s quit");
                    cancellationToken.ThrowIfCancellationRequested();
                    await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);

                    if (!IsNginxRunning())
                        LaunchNginxProcess($"-c \"{Path.GetFullPath("nginx.conf")}\"");

                    var lastUpdated = await GetLastUpdatedAsync(cancellationToken);
                    //   if (allActorsUpdated.ContainsKey(gateway.GetActorId()))
                    {
                        //     var updated = allActorsUpdated[gateway.GetActorId()];  // await gateway.GetLastUpdatedAsync();
                         
                        if (!lastWritten.Equals(lastUpdated))
                        {


                            await retryPolicy.ExecuteAsync(() => WriteConfigAsync(cancellationToken));


                            lastWritten = lastUpdated;
                            LaunchNginxProcess($"-c \"{Path.GetFullPath("nginx.conf")}\" -s reload");
                        }

                    }
                }

            }
            
            catch (Exception ex)
            {
                _logger.LogWarning(new EventId(), ex, "RunAsync Failed");
                throw;
            }




        }
        #endregion StatelessService


    }
}
