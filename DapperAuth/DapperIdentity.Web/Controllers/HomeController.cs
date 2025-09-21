using System.Web.Configuration;
using System.Web.Mvc;
using System.Web.Routing;

namespace App.Auth.Web.Controllers
{
    public class HomeController : Controller
    {
        private string DbName = string.Empty;
        protected override void Initialize(RequestContext requestContext)
        {
            base.Initialize(requestContext);
            if (Session["DatabaseName"] != null)
            {
                DbName = Session["DatabaseName"] == null ? "" : Session["DatabaseName"].ToString();
            }
        }
        public ActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {

                return Redirect(WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Dashboard/Index?from=appointments");
                //assignedsteps
                //return RedirectToAction("Index", "Dashboard");
            }
            else
            {
                return View();
            }
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}