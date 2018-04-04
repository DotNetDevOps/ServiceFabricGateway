using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Serilog;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore;
using SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Extensions;
using System;
using System.IO;
using System.Threading.Tasks;
using Unity;
using Unity.Builder;
using Unity.Builder.Strategy;
using Unity.Extension;
using Unity.Lifetime;
using Unity.Microsoft.DependencyInjection;
using Unity.Policy;
using Unity.Registration;

namespace SInnovations.ServiceFabric.IntegrationTests
{
    public class TestStartup
    {
        public TestStartup(IUnityContainer container)
        {
            var fact = container.Resolve<ILoggerFactory>();
            var logger = fact.CreateLogger<TestStartup>(); ;
            logger.LogInformation("Hello world");
        }
        public void ConfigureContainer(IUnityContainer container)
        {
            container.RegisterInstance("This string is displayed if container configured correctly",
                                       "This string is displayed if container configured correctly");


        }
        public void ConfigureServices(IServiceCollection services)
        {
        }

        public void Configure(IApplicationBuilder app)
        {
            app.Run(r => r.Response.WriteAsync("hello world"));
        }

    }

    public class a : IServiceProviderFactory<IServiceCollection>
    {
        public IServiceCollection CreateBuilder(IServiceCollection services)
        {
            return services;
        }

        public IServiceProvider CreateServiceProvider(IServiceCollection containerBuilder)
        {
            var a = new ServiceProviderFactory(null);
            var childchild = a.CreateBuilder(containerBuilder);
            var sp = a.CreateServiceProvider(childchild);
            return sp;
        }
    }

    public sealed class MyExtBuilder : BuilderStrategy
    {
        private MyExt myExt;

        public MyExtBuilder(MyExt myExt)
        {
            this.myExt = myExt;
        }

        public override void PreBuildUp(IBuilderContext context)
        {
            base.PreBuildUp(context);
        }
        public override void PostBuildUp(IBuilderContext context)
        {
            base.PostBuildUp(context);
        }
        public override bool RequiredToResolveInstance(IUnityContainer container, INamedType registration)
        {
            return base.RequiredToResolveInstance(container, registration);
        }
        public override bool RequiredToBuildType(IUnityContainer container, INamedType registration, params InjectionMember[] injectionMembers)
        {
            return base.RequiredToBuildType(container, registration, injectionMembers);
        }
    }

        public class MyExt : UnityContainerExtension
    {
        protected override void Initialize()
        {

         //   var strategy = new MyExtBuilder(this);
         //   this.Context.Strategies.Add(strategy, UnityBuildStage.Setup);

            foreach (var registration in Context.Container.Parent.Registrations)
            {
                if (registration.LifetimeManager is ContainerControlledLifetimeManager lifetime)
                {
                    lifetime.RemoveValue();
                  //  Context.Policies.Set(registration.MappedToType, string.Empty, typeof(IBuildPlanCreatorPolicy), new Test(Context.Policies));

                }
            }
        }
        public class Test : IBuildPlanCreatorPolicy
        {
            private IPolicyList policies;

            public Test(IPolicyList policies)
            {
                this.policies = policies;
            }

            public IBuildPlanPolicy CreatePlan(IBuilderContext context, INamedType buildKey)
            {

                return policies.Get< IBuildPlanPolicy>(buildKey);
            }
        }

        public ILifetimeContainer Lifetime => Context.Lifetime;
    }
        [TestClass]
    public class UnitTest1
    {
         private const string LiterateLogTemplate = "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message}{NewLine}{Exception}{NewLine}";


        /// <summary>
        /// This test passes and as expected does not dispose ILoggerFacyory
        /// </summary>
        [TestMethod]
        public void WithoutAspneteCore()
        {
            var container = new FabricContainer();

            container.ConfigureSerilogging(logConfiguration =>
                         logConfiguration.MinimumLevel.Information()
                         .Enrich.FromLogContext()
                         .WriteTo.LiterateConsole(outputTemplate: LiterateLogTemplate));

            var first = container.Resolve<ILoggerFactory>(); //Singleton / containercontrolled lifetime.

            var child = container.CreateChildContainer();

            var second = child.Resolve<ILoggerFactory>();
            Assert.AreEqual(first, second);

            child.Dispose();

           //Debugged, logger factory is not disposed.


        }
        /// <summary>
        /// The test fails as the second time IWebHost is running, the logger factory is disposed and it will fail due to this
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public async Task WithAspNetCore()
        {

            var container = new FabricContainer();

            container.ConfigureSerilogging(logConfiguration =>
                         logConfiguration.MinimumLevel.Information()
                         .Enrich.FromLogContext()
                         .WriteTo.LiterateConsole(outputTemplate: LiterateLogTemplate));

           

            {
                var child = container.CreateChildContainer();
                child.RegisterType<ILoggerFactory, LoggerFactory>(new ContainerControlledLifetimeManager());

                var childchi = child.CreateChildContainer();
                var first = childchi.Resolve<ILoggerFactory>(); //Singleton / containercontrolled lifetime.

                var second = child.Resolve<ILoggerFactory>();

              

                Assert.AreEqual(first, second);



                // But IloggerFactory is not disposed at this point.

            

                var builder = new WebHostBuilder()
                                   .UseKestrel()
                                   .ConfigureServices((b, s) =>
                                   {
                                       s.AddSingleton(child);
 
                                   })
                                   .UseUnityServiceProvider(child)
                                   .UseStartup<TestStartup>()
                                   .UseContentRoot(Directory.GetCurrentDirectory()).Build();

              

                //But when we dispose this, then ilogger factory will also get disposed. Why here but not above.
                (builder.Services as IDisposable).Dispose();

            
                //ILoggerFactory is now disposed.
            }

           
            {
                var child = container.CreateChildContainer();

                //Ilogger factory is the same, and therefore disposed and now this will fail.

                var builder = new WebHostBuilder()
                                   .UseKestrel()
                                   .ConfigureServices((b, s) =>
                                   {
                                       s.AddSingleton(child);
                                   })
                                   .UseUnityServiceProvider(child)
                                   .UseStartup<TestStartup>()
                                   .UseContentRoot(Directory.GetCurrentDirectory()).Build();
                
                   builder.Dispose();
            }



          


        }
    }
}
