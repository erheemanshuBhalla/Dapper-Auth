using App.Auth.Core.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DapperIdentity.Data
{
    public static class test
    {
        public static UserDataViewModel GetUsersData()
        {
            UserDataViewModel model = new UserDataViewModel();

            model.UserID = System.Web.HttpContext.Current.User.Identity.GetUserId();

            model.Is_roaming_retainer = false;
            model.Email = "bb";

            if (!string.IsNullOrEmpty(HttpContext.Current.Session["loggedin_role"] as string))
            {
                model.Role = HttpContext.Current.Session["loggedin_role"] as string;
            }
            else
            {
                model.Role = "Admin";
            }

            model.Is_Authenticated = HttpContext.Current.User.Identity.IsAuthenticated;
            model.Name = HttpContext.Current.User.Identity.Name;

            model.OfficeId = 4;
            return model;
        }
    }
}
