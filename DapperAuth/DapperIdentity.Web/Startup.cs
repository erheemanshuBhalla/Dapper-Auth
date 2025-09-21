using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(App.Auth.Web.Startup))]
namespace App.Auth.Web
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
