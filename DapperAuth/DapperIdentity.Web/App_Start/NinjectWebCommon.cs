using System;
using System.Configuration;
using System.Web;
using App.Auth.Core.Entities;
using App.Auth.Core.Interfaces;
using App.Auth.Data.Connections;
using App.Auth.Data.Repositories;
using App.Auth.Web;
using Microsoft.AspNet.Identity;
using Microsoft.Web.Infrastructure.DynamicModuleHelper;
//using Ninject;
//using Ninject.Web.Common;


//[assembly: WebActivatorEx.PreApplicationStartMethod(typeof(NinjectWebCommon), "Start")]
//[assembly: WebActivatorEx.ApplicationShutdownMethodAttribute(typeof(NinjectWebCommon), "Stop")]

namespace App.Auth.Web
{
    //public static class NinjectWebCommon
    //{
    //    private static readonly Bootstrapper bootstrapper = new Bootstrapper();

    //    /// <summary>
    //    /// Starts the application
    //    /// </summary>
    //    public static void Start()
    //    {
    //        DynamicModuleUtility.RegisterModule(typeof(OnePerRequestHttpModule));
    //        DynamicModuleUtility.RegisterModule(typeof(NinjectHttpModule));
    //        bootstrapper.Initialize(CreateKernel);
    //    }

    //    /// <summary>
    //    /// Stops the application.
    //    /// </summary>
    //    public static void Stop()
    //    {
    //        bootstrapper.ShutDown();
    //    }

    //    /// <summary>
    //    /// Creates the kernel that will manage your application.
    //    /// </summary>
    //    /// <returns>The created kernel.</returns>
    //    private static IKernel CreateKernel()
    //    {
    //        var kernel = new StandardKernel();
    //        try
    //        {
    //            kernel.Bind<Func<IKernel>>().ToMethod(ctx => () => new Bootstrapper().Kernel);
    //            kernel.Bind<IHttpModule>().To<HttpApplicationInitializationHttpModule>();

    //            RegisterServices(kernel);
    //            return kernel;
    //        }
    //        catch
    //        {
    //            kernel.Dispose();
    //            throw;
    //        }
    //    }

    //    /// <summary>
    //    /// Load your modules or register your services here!
    //    /// </summary>
    //    /// <param name="kernel">The kernel.</param>
    //    private static void RegisterServices(IKernel kernel)
    //    {
    //        kernel.Bind<IConnectionFactory>().To<SqlConnectionFactory>().WithConstructorArgument("connectionString", ConfigurationManager.ConnectionStrings["ICMS_AUTH_QA_CONN"].ConnectionString);
    //        //kernel.Bind<IConnectionFactory>().To<SqlConnectionFactory>().WithConstructorArgument("connectionString", ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString);
    //        kernel.Bind<IUserRepository>().To<UserRepository>();
    //        kernel.Bind<IRoleRepository>().To<RoleRepository>();
    //        kernel.Bind<IUserStore<ApplicationUser>>().To<UserRepository>();
    //        kernel.Bind<IUserLoginStore<ApplicationUser>>().To<UserRepository>();
    //        kernel.Bind<IUserPasswordStore<ApplicationUser>>().To<UserRepository>();
    //        kernel.Bind<IUserSecurityStampStore<ApplicationUser>>().To<UserRepository>();
    //        kernel.Bind(typeof(UserManager<>)).ToSelf();
    //    }
    //}
}
