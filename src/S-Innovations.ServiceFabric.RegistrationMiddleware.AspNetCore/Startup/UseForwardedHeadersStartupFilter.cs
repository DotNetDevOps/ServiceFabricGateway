using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.HttpOverrides.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using System;
using System.Linq;
using System.Net;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Startup
{
    public class UseForwardedHeadersStartupFilter : IStartupFilter
    {
        private const string XForwardedPathBase = "X-Forwarded-PathBase";
        private readonly string serviceFabricKey;
        private readonly ILogger logger;

        public UseForwardedHeadersStartupFilter(string serviceFabricKey, ILogger logger)
        {
            this.serviceFabricKey = serviceFabricKey;
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> nextBuilder)
        {
            return builder =>
            {
                builder.UseForwardedHeaders(new ForwardedHeadersOptions
                {
                    ForwardedHeaders = ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto
                });

                builder.Use(async (context, next) =>
                {
                    if (context.Request.Headers.TryGetValue("X-ServiceFabric-Key", out StringValues serviceFabricKey))
                    {
                        //TODO, Readd without version when version bumps
                        //if (!serviceFabricKey.FirstOrDefault().Equals(this.serviceFabricKey))
                        //{
                        //    logger.LogWarning("X-ServiceFabric-Key mismatch: {actual} {expected}", serviceFabricKey, this.serviceFabricKey);
                        //    context.Response.StatusCode = StatusCodes.Status410Gone;
                        //    return;
                        //}
                    }

                    if (context.Request.Headers.TryGetValue("X-Forwarded-For", out StringValues XForwardedFor))
                    {
                        var parsed = IPEndPointParser.TryParse(XForwardedFor.SelectMany(k=>k.Split(',')).First(), out IPEndPoint remoteIP);
                        logger.LogInformation("X-Forwarded-For = {XForwardedFor} {Length}, Parsed={parsed}, remoteIp={oldRemoteIP}/{remoteIP}", string.Join(",", XForwardedFor), XForwardedFor.Count, parsed, context.Connection.RemoteIpAddress, parsed ? remoteIP : null);
                        if (parsed)
                        {
                            context.Connection.RemoteIpAddress = remoteIP.Address;
                        }
                    }
                    else
                    {
                        logger.LogInformation("No X-Forwarded-For: {Request} {Path} {REmoteIpAddress} ", context.Request.Host, context.Request.Path, context.Connection.RemoteIpAddress);
                    }

                    var original = context.Request.PathBase;
                    try
                    {
                        if (context.Request.Headers.TryGetValue(XForwardedPathBase, out StringValues value))
                        {
                            context.Request.PathBase = new PathString(value);
                        }


                        await next();


                    }
                    finally
                    {
                        context.Request.Path = context.Request.PathBase + context.Request.Path;
                        context.Request.PathBase = original;

                    }

                });

                nextBuilder(builder);


            };
        }

    }
}
