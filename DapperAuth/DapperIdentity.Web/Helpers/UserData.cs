using App.Auth.Core.Entities;
using App.Auth.Core.ViewModels;
using App.ICMS.Data.DataMethods;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.DataProtection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace App.Auth.Web
{
    public  static class UserData
    {
        public static string resetcode(string uid)
        {
            string result = "";

            var _userManager = HttpContext.Current.GetOwinContext().GetUserManager<UserManager<ApplicationUser>>();
            /* User Validator */
            //var provider = new DpapiDataProtectionProvider("App_Auth_Web");


            //var dataProtectionProvider = options.DataProtectionProvider;
            //if (dataProtectionProvider != null)
            {
                //_userManager.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            //_userManager.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser>(provider.Create("App_Auth_Web"));

            string code = _userManager.GeneratePasswordResetToken(uid);
            result = code;
            return result;
        }

        public static UserDataViewModel GetUsersData(string dbname_)
        {
            UserDataViewModel model = new UserDataViewModel();

            
            model.UserID = HttpContext.Current.User.Identity.GetUserId();
            model.Is_Authenticated = HttpContext.Current.User.Identity.IsAuthenticated;
            model.Name = HttpContext.Current.User.Identity.Name;

            var _userdata=UserMethods.GetUserData(model.UserID, dbname_);

            model.Is_roaming_retainer = _userdata.Is_roaming_retainer;
            model.Email = _userdata.Email;
            
                if (!string.IsNullOrEmpty(HttpContext.Current.Session["loggedin_role"] as string))
                {
                    model.Role = HttpContext.Current.Session["loggedin_role"] as string;
                }
                else
                {
                model.Role = _userdata.Role;
                }
            
            

            model.OfficeId = _userdata.OfficeId;
            return model;
        }
    }
}