using Unity;
using SInnovations.ServiceFabric.Unity;
using SInnovations.Unity.AspNetCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting.Internal;
using Microsoft.Extensions.Configuration;
using System.Reflection;
using System;
using System.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Unity.Lifetime;
//#if NETCORE20
using Unity.Microsoft.DependencyInjection;
using Unity.Extension;
using Unity.Policy;
using Unity.Builder;
using System.Linq;

//#endif

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore
{

    public class LoggingExtension : UnityContainerExtension,
                                   IBuildPlanCreatorPolicy,
                                   IBuildPlanPolicy
    {
        #region Fields

        private readonly MethodInfo _createLoggerMethod = typeof(LoggingExtension).GetTypeInfo()
                                                                                  .GetDeclaredMethod(nameof(CreateLogger));

        #endregion


        #region Constructors

        //[InjectionConstructor]
        //public LoggingExtension()
        //{
        //    LoggerFactory = new LoggerFactory();
        //}

        //public LoggingExtension(ILoggerFactory factory)
        //{
        //    LoggerFactory = factory ?? new LoggerFactory();
        //}


        #endregion


        #region Public Members

        //public ILoggerFactory LoggerFactory { get; }

        #endregion


        #region IBuildPlanPolicy


        public void BuildUp(IBuilderContext context)
        {
            context.Existing = null == context.ParentContext
                             ? context.Container.Resolve<ILoggerFactory>().CreateLogger(context.OriginalBuildKey?.Name ?? string.Empty)
                             : context.ParentContext.Container.Resolve<ILoggerFactory>().CreateLogger(context.ParentContext?.BuildKey?.Type ?? this.GetType());

            context.BuildComplete = true;
        }

        #endregion


        #region IBuildPlanCreatorPolicy

        IBuildPlanPolicy IBuildPlanCreatorPolicy.CreatePlan(IBuilderContext context, INamedType buildKey)
        {
            var info = (context ?? throw new ArgumentNullException(nameof(context))).BuildKey
                                                                                    .Type
                                                                                    .GetTypeInfo();
            if (!info.IsGenericType) return this;

            var buildMethod = _createLoggerMethod.MakeGenericMethod(info.GenericTypeArguments.First())
                                                 .CreateDelegate(typeof(DynamicBuildPlanMethod));

            return new DynamicMethodBuildPlan((DynamicBuildPlanMethod)buildMethod, context.Container.Resolve<ILoggerFactory>());
        }

        #endregion


        #region Implementation

        private static void CreateLogger<T>(IBuilderContext context, ILoggerFactory loggerFactory)
        {
            context.Existing = loggerFactory.CreateLogger<T>();
            context.BuildComplete = true;
        }

        protected override void Initialize()
        {
            Context.Policies.Set(typeof(ILogger), string.Empty, typeof(IBuildPlanPolicy), this);
            Context.Policies.Set<IBuildPlanCreatorPolicy>(this, typeof(ILogger));
            Context.Policies.Set<IBuildPlanCreatorPolicy>(this, typeof(ILogger<>));
        }

        private delegate void DynamicBuildPlanMethod(IBuilderContext context, ILoggerFactory loggerFactory);

        private class DynamicMethodBuildPlan : IBuildPlanPolicy
        {
            private readonly DynamicBuildPlanMethod _buildMethod;
            private readonly ILoggerFactory _loggerFactory;

            /// <summary>
            /// 
            /// </summary>
            /// <param name="buildMethod"></param>
            /// <param name="loggerFactory"></param>
            public DynamicMethodBuildPlan(DynamicBuildPlanMethod buildMethod,
                                          ILoggerFactory loggerFactory)
            {
                _buildMethod = buildMethod;
                _loggerFactory = loggerFactory;
            }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="context"></param>
            public void BuildUp(IBuilderContext context)
            {
                _buildMethod(context, _loggerFactory);
            }
        }

        #endregion
    }

    public class FabricContainer : UnityContainer, IServiceScopeInitializer
    {

        private static string ResolveContentRootPath(string contentRootPath, string basePath)
        {
            if (string.IsNullOrEmpty(contentRootPath))
            {
                return basePath;
            }
            if (Path.IsPathRooted(contentRootPath))
            {
                return contentRootPath;
            }
            return Path.Combine(Path.GetFullPath(basePath), contentRootPath);
        }

        public FabricContainer(ServiceCollection services =null)
        {
            services = services ?? new ServiceCollection();
            this.AddNewExtension<LoggingExtension>();
         //s   this.AddExtension(new EnumerableExtension());

            this.RegisterInstance<IServiceScopeInitializer>(this);

//#if NETCORE20

            this.AsFabricContainer().BuildServiceProvider(services) ;
//#else
//            this.AsFabricContainer().WithAspNetCoreServiceProvider();
//#endif

            var _hostingEnvironment = new HostingEnvironment();
            var _config = new ConfigurationBuilder()
                .AddEnvironmentVariables(prefix: "ASPNETCORE_")
                .Build();
            var _options = new WebHostOptions(_config, Assembly.GetEntryAssembly()?.GetName().Name)
            {
                
            };
           // Microsoft.AspNetCore.Hosting.Internal.HostingEnvironmentExtensions.Initialize

            var contentRootPath = ResolveContentRootPath(_options.ContentRootPath, AppContext.BaseDirectory); 
            _hostingEnvironment.Initialize(contentRootPath, _options);
            this.RegisterInstance<IHostingEnvironment>(_hostingEnvironment);
        }
        public IUnityContainer InitializeScope(IUnityContainer container)
        {
//#if NETCORE20

            var child = container.CreateChildContainer()
                .RegisterType<ILoggerFactory, LoggerFactory>(new ContainerControlledLifetimeManager());

            child.BuildServiceProvider(new ServiceCollection());
            return child;

          //  var child= fac.CreateBuilder();

         //   fac.CreateServiceProvider(child);

        //    return child;
//#else
//            return container.WithAspNetCoreServiceProvider();
//#endif
        }

       
    }
}
