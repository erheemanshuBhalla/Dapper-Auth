using App.Auth.Core.Entities;
using App.Auth.Core.Interfaces;
using App.ICMS.Data.DataMethods;
using App.ICMS.Data.ViewModels;
using HtmlAgilityPack;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.DataProtection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;
using System.Web.Routing;

namespace App.Auth.Web.Controllers
{
    public class UsersController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private IRoleRepository _roleRepository;
        private IUserRepository _userRepository;
        private IConnectionFactory _connection;

        private string DbName = string.Empty;
        protected override void Initialize(RequestContext requestContext)
        {
            base.Initialize(requestContext);
            if (Session["DatabaseName"] != null)
            {
                DbName = Session["DatabaseName"] == null ? "" : Session["DatabaseName"].ToString();
            }
        }
        public UsersController(UserManager<ApplicationUser> userManager, IRoleRepository rolerepository, IConnectionFactory connection,IUserRepository userrepository)
        {
            
        //=== DbName = Session["DatabaseName"] == null ? "" : Session["DatabaseName"].ToString();
        _userManager = userManager;
            _roleRepository = rolerepository;
            _connection = connection;
            _userRepository = userrepository;
            _userManager.UserValidator = new UserValidator<ApplicationUser>(_userManager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };
            // Configure validation logic for passwords
            _userManager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            // Configure user lockout defaults
            _userManager.UserLockoutEnabledByDefault = false;
            _userManager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            _userManager.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug it in here.
            _userManager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<ApplicationUser>
            {
                MessageFormat = "Your security code is {0}"
            });
            _userManager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<ApplicationUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });
            _userManager.EmailService = new EmailService();
            _userManager.SmsService = new SmsService();
            var provider = new DpapiDataProtectionProvider("App_Auth_Web");
            userManager.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser>(
    provider.Create("App_Auth_Web"));
        }
        // GET: User

        // GET: Users
        //Id=userid and officeid=officeid
        [Authorize]
        public ActionResult Index(string id, int officeid = 0)
        {
            ViewBag.SuccessMessage = "";
            var user = UserData.GetUsersData(DbName);
            ViewBag.loggedinRole = user.Role.ToString(); //=== UserData.GetUsersData(DbName).Role;
            if(officeid==0)
            officeid = user.OfficeId;
            ViewBag.SelecedOffice = officeid;
            ViewBag.isroamingretainer = false;

            bool is_roamingretainer = user.Is_roaming_retainer; //=== UserData.GetUsersData(DbName).Is_roaming_retainer;
            ViewBag.isroamingretainer = is_roamingretainer;

            if (User.IsInRole("Manager") | is_roamingretainer == true)
            {
                ViewBag.Offices = new SelectList(OfficesMethods.GetAllOffice(CompanyMethods.GetCompanyByOfficeId(officeid, DbName), DbName), "Id", "Name", officeid);

                if ((id != null) && (id.Length > 0))
                {
                    ViewBag.SuccessMessage = "User has been successfully added";
                    return View(UserMethods.get_users_with_roles(id, officeid, user.Role, DbName)); 
                }
                return View(UserMethods.get_users_with_roles("", officeid, user.Role, DbName)); 
            }
            else if (User.IsInRole("Admin") || User.IsInRole("Office Manager") || User.IsInRole("Processor"))
            {
                if ((id != null) && (id.Length > 0))
                {
                    ViewBag.SuccessMessage = "User has been successfully added";
                    return View(UserMethods.get_users_with_roles(id, user.OfficeId, user.Role, DbName)); 
                }
                return View(UserMethods.get_users_with_roles("", officeid, user.Role, DbName)); 
            }

            string userid = User.Identity.GetUserId();
            return View(UserMethods.get_users_with_roles(userid, officeid, user.Role, DbName)); 
        }


        //public ActionResult Delete(string id)
        //{
        //    AspNetUser aspNetUser = db.AspNetUsers.Find(id);
        //    aspNetUser.EmailConfirmed = false;

        //    //change here
        //    //db.Entry(aspNetUser).State = EntityState.Modified;
        //    //db.SaveChanges();
        //    return RedirectToAction("Index");

        //}
        public ActionResult Deleteagreement(string userid)
        {
            AgreementMethods.Deleteagreement(userid, DbName);
            return RedirectToAction("Edit", new { id = userid });

        }

        // GET: AspNetUsers/Edit/5
        public ActionResult Edit(string id,string from="")

        {
            ViewBag.Pagename = "Edit";
            ViewBag.from = from;
            ViewBag.Id = id;
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            //AspNetUser aspNetUser = db.AspNetUsers.Find(id);
            AspNetUser aspNetUser = UserMethods.Get_User_By_Id(id, DbName);

            var address_details = ClientMethods.GetAgentaddress(id, DbName);
            aspNetUser.Address = address_details.Address;
            aspNetUser.City = address_details.City;

            if ((UserData.GetUsersData(DbName).Role == "Manager") || (UserData.GetUsersData(DbName).Is_roaming_retainer == true))
            {
                int companyid = CompanyMethods.GetCompanyByOfficeId(UserData.GetUsersData(DbName).OfficeId,DbName);
                var Offices_lst = OfficesMethods.GetAllOffice(companyid, DbName);
                ViewBag.Offices = new SelectList(Offices_lst, "Id", "Name", aspNetUser.OfficeId);
                ViewBag.Show = "Yes";
            }
            else
            {
                ViewBag.Show = "No";
                ViewBag.Offices = UserData.GetUsersData(DbName).OfficeId;
            }

            if(ViewBag.from== "viewuserprofile")
                ViewBag.Show = "No";

            string res = CompanyMethods.GetAgreementPath_by_userid(id, DbName);
            if (res.Length > 0)
            {
                ViewBag.Agreementurl = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + CompanyMethods.GetAgreementPath_by_userid(id, DbName);
            }
            else
            {
                ViewBag.Agreementurl = "#";
            }

            var roleList = UserMethods.get_all_roles();
            var user_roles =  UserMethods.get_userroles(id);
            List<string> _vals = new List<string>();

            for (int i = 0; i <= user_roles.Count - 1; i++)
            {
                //_vals[i] = aspNetUser.AspNetRoles.ElementAt(i).Id;
                _vals.Add(user_roles.ElementAt(i).Id);
            }

            IEnumerable<string> usersIds = _vals.AsEnumerable<string>();

            ViewBag.Roles = new MultiSelectList(roleList.ToList(), "Id", "Name", usersIds);
            if (aspNetUser == null)
            {
                return HttpNotFound();
            }
            ViewBag.UserID = id;
            return View(aspNetUser);
        }

        // POST: AspNetUsers/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ValidateInput(false)]
        public ActionResult Edit([Bind(Include = "Id,Email,EmailConfirmed,PasswordHash,SecurityStamp,PhoneNumber,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEndDateUtc,LockoutEnabled,AccessFailedCount,UserName,OfficeId,FirstName,LastName,UserRoles,Password,ConfirmPassword,Files,agreementfile,Is_roaming_retainer,Is_contract_owner,Canoverride,PhoneNumber,City,Address")] AspNetUser aspNetUser, string[] userroles1, string id, string editor1,string cmb_default_roles, string posttype = "Save",string from="")
        {
            ViewBag.Pagename = "Edit";
            ViewBag.from = from;
            if (editor1 == null)
                editor1 = "";
            ViewBag.from = "Main";

            if (editor1.Length > 0)
            {
                ViewBag.from = "Agreement";
                //Post of Editor Tab
                ViewBag.editor1 = editor1;

                HtmlDocument doc = new HtmlDocument();
                string prep = "<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN' 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'> <html xmlns='http://www.w3.org/1999/xhtml'> <head> <meta http-equiv='Content-Type' content='text/html; charset=utf-8' /> <link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css'/> <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css'/><head> </head>  <body>";
                string lastp = "</body></html>";
                doc.LoadHtml(prep + editor1 + lastp);
                //doc.Save("d://test.html");
                //int companyid = CompanyMethods.GetCompanyByOfficeId(UserData.GetUsersData(DbName).OfficeId);

                string path = "/Content/Images/admission_edit_" + id + ".html";
                doc.Save(Server.MapPath("~" + path));
                ViewBag.editor1 = path;
                ViewBag.posttype = posttype;

                ViewBag.Pagename = "Edit";

                //AspNetUser aspNetUser1 = db.AspNetUsers.Find(id);
                AspNetUser aspNetUser1 = UserMethods.Get_User_By_Id(id, DbName);

                var address_details = ClientMethods.GetAgentaddress(id, DbName);
                aspNetUser1.Address = address_details.Address;
                aspNetUser1.City = address_details.City;

                if ((UserData.GetUsersData(DbName).Role == "Manager") || (UserData.GetUsersData(DbName).Is_roaming_retainer == true))
                {
                    int companyid = CompanyMethods.GetCompanyByOfficeId(UserData.GetUsersData(DbName).OfficeId, DbName);
                    var Offices_lst = OfficesMethods.GetAllOffice(companyid, DbName);
                    ViewBag.Offices = new SelectList(Offices_lst, "Id", "Name", aspNetUser.OfficeId);
                    ViewBag.Show = "Yes";
                }
                else
                {
                    ViewBag.Show = "No";
                    ViewBag.Offices = UserData.GetUsersData(DbName).OfficeId;
                }


                string res = CompanyMethods.GetAgreementPath_by_userid(id, DbName);
                if (res.Length > 0)
                {
                    ViewBag.Agreementurl = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + CompanyMethods.GetAgreementPath_by_userid(id, DbName);
                }
                else
                {
                    ViewBag.Agreementurl = "#";
                }

                var roleList = UserMethods.get_all_roles();

                List<string> _vals = new List<string>();
                
                for (int i = 0; i <= aspNetUser1.AspNetRoles.Count - 1; i++)
                {
                    //_vals[i] = aspNetUser.AspNetRoles.ElementAt(i).Id;
                    _vals.Add(aspNetUser1.AspNetRoles.ElementAt(i).Id);
                }

                IEnumerable<string> usersIds = _vals.AsEnumerable<string>();

                ViewBag.Roles = new MultiSelectList(roleList.ToList(), "Id", "Name", usersIds);
                if (aspNetUser == null)
                {
                    return HttpNotFound();
                }
                ViewBag.UserID = id;
                return View(aspNetUser1);
            }
            else
            {
                if (ModelState.IsValid)
                {
                    if (User.IsInRole("Case Coordinator"))
                    {
                        //aspNetUser.OfficeId = 0;
                    }

                    //AspNetUser aspNetUser_update = db.AspNetUsers.Find(aspNetUser.Id);
                    AspNetUser aspNetUser_update = UserMethods.Get_User_By_Id(aspNetUser.Id, DbName);
                    aspNetUser_update.Is_contract_owner = aspNetUser.Is_contract_owner;
                    aspNetUser_update.Canoverride = aspNetUser.Canoverride;
                    aspNetUser_update.FirstName = aspNetUser.FirstName;
                    aspNetUser_update.LastName = aspNetUser.LastName;
                    aspNetUser_update.OfficeId = aspNetUser.OfficeId;
                    aspNetUser_update.Email = aspNetUser.Email;
                    aspNetUser_update.EmailConfirmed = aspNetUser.EmailConfirmed;
                    aspNetUser_update.Is_roaming_retainer = aspNetUser.Is_roaming_retainer;
                    aspNetUser_update.UserName = aspNetUser.FirstName + " " + aspNetUser.LastName;
                    aspNetUser_update.PhoneNumber = aspNetUser.PhoneNumber;
                    aspNetUser_update.default_role = cmb_default_roles;
                    aspNetUser_update.Id = aspNetUser.Id;
                    UserMethods.UpdateUser(aspNetUser_update);
                    //change here
                    //db.Entry(aspNetUser_update).State = EntityState.Modified;
                    //db.SaveChanges();

                    if (aspNetUser.City != null)
                    {
                        if (aspNetUser.City.Length > 0)
                        {
                            ClientRegisterViewModel _m = new ClientRegisterViewModel();
                            _m.Address = aspNetUser.Address;

                            string[] lst = aspNetUser.City.Split(',');
                            _m.City = lst[0];
                            _m.Country = lst[2];
                            _m.State = lst[1];
                            _m.referenceid = aspNetUser.Id;

                            ClientMethods.Update_User_Address(_m, DbName);
                        }
                    }
                    //if (userroles1.Contains("6d79294a-c227-47d4-afa8-0353f93648a9") || userroles1.Contains("6b2b8a1f-73e6-49e6-80f8-d808bb3b334a") || userroles1.Contains("bfde9ab4-d5a8-41b5-92e2-57848215faa5"))
                    //{
                    /* update Accounts Table */
                    var aaccid = LedgerAccountsMethods.GetAccountId_by_StrRefId(aspNetUser.Id, DbName);
                    if (aaccid == null)
                    {
                        /* Insert into Accounts Table */
                        AccountsViewModel ins = new AccountsViewModel();
                        ins.Name = aspNetUser.FirstName + " " + aspNetUser.LastName;
                        ins.ReferenceId = 0;
                        ins.str_ReferenceId = aspNetUser.Id;
                        ins.officeid = aspNetUser.OfficeId;
                        ins.AccountType = "User Account";
                        ins.companyid = CompanyMethods.GetCompanyByOfficeId(aspNetUser.OfficeId, DbName);
                        string startYear = Convert.ToDateTime(Session["YearStartDate"]).Year.ToString();
                        string endYear = Convert.ToDateTime(Session["YearEndDate"]).Year.ToString();
                        ins.Years = startYear + "-" + endYear;
                        ClientMethods.Insert_Account(ins, DbName);
                    }
                    else
                    {
                        /*Updat4e Account*/
                        AccountsViewModel d = new AccountsViewModel();
                        d.Name = aspNetUser.FirstName + " " + aspNetUser.LastName;
                        d.str_ReferenceId = aspNetUser.Id;
                        ClientMethods.update_Account(d, DbName);
                    }


                    //}

                    //Update User Edited Role 
                    //AspNetUser aspNetUser1 = db.AspNetUsers.Find(aspNetUser.Id);
                    AspNetUser aspNetUser1 = UserMethods.Get_User_By_Id(aspNetUser.Id, DbName);
                    List<string> _vals = new List<string>();

                    for (int i = 0; i <= aspNetUser1.AspNetRoles.Count - 1; i++)
                    {
                        //_vals[i] = aspNetUser.AspNetRoles.ElementAt(i).Id;
                        _vals.Add(aspNetUser1.AspNetRoles.ElementAt(i).Id);
                    }
                    if (userroles1 != null)
                    {
                        IEnumerable<string> usersIds = _vals.AsEnumerable<string>();

                        var roles = ((ClaimsIdentity)User.Identity).Claims
                        .Where(c => c.Type == ClaimTypes.Role)
                        .Select(c => c.Value);


                        //for (int i = 0; i <= aspNetUser.AspNetRoles.Count - 1; i++)
                        foreach (var item in usersIds)
                        {
                            UserMethods.RemoveUserrole(aspNetUser.Id, item);
                        }

                        _userManager.RemoveFromRoles(aspNetUser.Id, usersIds.ToArray<string>());

                        //Assign Role to user Here      
                        foreach (var item in userroles1)
                        {
                            //var rolename =UserMethods.get_all_roles().Where(x => x.Id == item).Select(x => x.Name).SingleOrDefault();
                            _userManager.AddToRole(aspNetUser.Id, item);

                            //OfficesMethods.update_user_role(aspNetUser.Id, item);
                        }

                    }

                    //update password
                    if (aspNetUser.Password != null)
                    {
                        if (aspNetUser.Password.Length > 0)
                        {
                            string code = _userManager.GeneratePasswordResetToken(aspNetUser.Id);
                            _userManager.ResetPassword(aspNetUser.Id, code, aspNetUser.Password);
                        }
                    }
                    if (from == "viewuserprofile")
                    {
                        return RedirectToAction("Saved", "Data", new { message = "User has been updated successfully", returnurl = "/Users/Edit/"+aspNetUser.Id+"?from=" + from });
                    }
                    else
                    {
                        return RedirectToAction("Saved", "Data", new { message = "User has been updated successfully", returnurl = "/Users/Index?from=" + from });
                    }
                    //return RedirectToAction("Index");
                }
                return View(aspNetUser);
            }

        }

    }
}