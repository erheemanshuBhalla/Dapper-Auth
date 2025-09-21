using Microsoft.Owin.Security.DataProtection;
using Microsoft.AspNet.Identity.Owin;

using System;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using App.Auth.Core.Entities;
using App.Auth.Web.Email;

using App.Auth.Data.Repositories;
using App.ICMS.Data.DataMethods;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using ExternalLoginConfirmationViewModel = App.Auth.Web.ViewModels.ExternalLoginConfirmationViewModel;
using ForgotPasswordViewModel = App.Auth.Web.ViewModels.ForgotPasswordViewModel;
using LoginViewModel = App.Auth.Web.ViewModels.LoginViewModel;
using RegisterViewModel = App.Auth.Web.ViewModels.RegisterViewModel;
using ResetPasswordViewModel = App.Auth.Web.ViewModels.ResetPasswordViewModel;
using App.Auth.Core.Interfaces;
using System.Linq;
using System.Collections.Generic;
using App.ICMS.Data.ViewModels;
using System.Web.Configuration;
using App.Auth.Core.ViewModels;
using System.Web.Routing;
using App.ICMS.Data.Methods;
using System.Text;
using Newtonsoft.Json;

namespace App.Auth.Web.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        
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
        public AccountController(UserManager<ApplicationUser> userManager,IConnectionFactory connection)
        {
            _userManager = userManager;
            //_roleRepository = rolerepository;
            _connection = connection;
                                    
            /* User Validator */
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


            //var dataProtectionProvider = options.DataProtectionProvider;
            //if (dataProtectionProvider != null)
            {
                //_userManager.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            _userManager.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser>(
    provider.Create("App_Auth_Web"));

            /* User Validator */
        }

        [AllowAnonymous]
        public ActionResult PublicLogin(string encrypted_data)
        {
            //var data = EmailConfirmationHelper.DecodeConfirmationToken(encrypted_data);
            var bytes = HttpServerUtility.UrlTokenDecode(encrypted_data);
            var jsonString = Encoding.UTF8.GetString(bytes);
            var data= JsonConvert.DeserializeObject<ConfirmationToken>(jsonString);

            //AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            var AuthenticationManager = HttpContext.GetOwinContext().Authentication;
            CheckSigin(data.Email.TrimEnd(), data.Token);
            var user = _userManager.FindByEmail(data.Email);
            var identity =  _userManager.CreateIdentity(user, DefaultAuthenticationTypes.ApplicationCookie);
            AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = true }, identity);
            //SignInAsync(user, true);
            // return RedirectToAction("Index", "Dashboard");
            /* After Login */
            var login_user = _userManager.FindById(user.Id);
            bool Is_roaming_retainer = login_user.Is_roaming_retainer;
            string _role = "";
            {
                _role = login_user.default_role;
                Session["loggedin_role"] = _role;
            }
            Session["Role"] = _role;
            Session["DatabaseName"] = login_user.DatabaseName;
            if (string.IsNullOrEmpty(login_user.DatabaseName))
            {
                //===;
            }
            else
            {
                DbName = login_user.DatabaseName;
            }
            int companyid = CompanyMethods.GetCompanyByOfficeId(_userManager.FindById(user.Id).OfficeId, login_user.DatabaseName);
            var companydetails = CompanyMethods.GetCompanyById(companyid);
            var AddDate = companydetails.AddDate.AddDays(7);
            var difference = DateTime.Now.Subtract(AddDate).Days;
            if (companydetails.PlanId == 1)
            {
                if (difference > 2)
                {
                    Session["Headermessage"] = "7-Day Free Trial Activated! " + difference.ToString() + " Days Left <a href='" + WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Customer/PaymentDetails/' class='btn btn-default btn-lg'>Upgrade Now</a>";
                }
                else
                {
                    Session["Headermessage"] = "Your Trial is Ending Soon! Don’t Lose Access. <a href='" + WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Customer/PaymentDetails/' class='btn btn-default btn-lg'>Upgrade Now</a>";
                }
            }
            else
            {
                Session["Headermessage"] = "";
            }
            string companyname = companydetails.Name;
            bool EnableAdmissions = companydetails.EnableAdmissions;
            Session["CompanyId"] = companyid;
            Session["PlanId"] = companydetails.PlanId;
            Session["EnableAdmissions"] = EnableAdmissions;
            Session["PaidConsultation"] = companydetails.PaidConsultation;
            if (string.IsNullOrEmpty(companydetails.LogoUrl))
            {
                Session["CompanyLogo"] = "immracio-logo.jpg";
                Session["CompanyLogo"] = companyid.ToString() + ".jpg";
            }
            else
            {
                Session["CompanyLogo"] = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + companydetails.LogoUrl.ToString(); //=== "immracio-logo.jpg";
            }

            if (string.IsNullOrEmpty(companyname))
            {
                Session["CompanyName"] = "Immracio";
            }
            else
            {
                Session["CompanyName"] = companyname;
            }
            Session["YearStartDate"] = companydetails.YearStartDate;
            Session["YearEndDate"] = companydetails.YearEndDate;
            string[] splitarray_start = companydetails.YearStartDate.ToString().Split(' ')[0].ToString().Split('/');
            string[] splitarray_end = companydetails.YearEndDate.ToString().Split(' ')[0].ToString().Split('/');
            string current_year_status = splitarray_start[2] + "-" + splitarray_end[2];
            Session["YearStatus"] = ConfigurationMethods.GetYearsStatus(current_year_status, DbName);
            string clogo = Session["CompanyLogo"].ToString();
            string cname = Session["CompanyName"].ToString();
            if ((_role != "Manager") && (Is_roaming_retainer == false) && (_role != "Case Coordinator"))
            {
                Session["Office"] = "";
                if (_role != "Admin")
                {
                    int office_id = _userManager.FindById(user.Id).OfficeId;
                    Session["Office"] = OfficesMethods.GetOfficeById(office_id, DbName).Name;
                }
            }
            else
            {
                Session["Office"] = "";
            }


            /* After Login */
            //returnUrl = returnUrl == null ? "~/Home/Index" : returnUrl;

            return RedirectToAction("Index","Home");




            //return Redirect("http://qa.nanojot.com/Immraciobeta/Application/webapp/");
        }


        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            var AuthenticationManager = HttpContext.GetOwinContext().Authentication;
            AuthenticationManager.SignOut();
            Request.GetOwinContext().Authentication.SignOut();

            Request.GetOwinContext().Authentication.SignOut(Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ApplicationCookie);

            HttpContext.GetOwinContext().Authentication.SignOut(Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ApplicationCookie);
            
            string name = User.Identity.GetUserName();

            Session.Remove("Office");
            Session.Remove("loggedin_role");
            Session.Clear();
            Session.RemoveAll();
            Session.Abandon();
            Response.AddHeader("Cache-control", "no-store, must-revalidate, private, no-cache");
            Response.AddHeader("Pragma", "no-cache");
            Response.AddHeader("Expires", "0");

            return View();
        }
        [HttpPost]
        public JsonResult checksession()
        {
            bool data1 = User.Identity.IsAuthenticated;

            return Json(data1, JsonRequestBehavior.AllowGet);
        }
        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                if (string.IsNullOrEmpty(model.Email) || string.IsNullOrEmpty(model.Password))
                {
                    ModelState.AddModelError("", "Invalid login attempt. User Name and Passward Required.");
                    return View(model);
                }

                //check to see if the account exists
                ApplicationUser user;
                //var user = await _userManager.FindAsync(model.Email.TrimEnd(), model.Password);
                if (model.Email.Contains("@"))
                {
                    user = await _userManager.FindByEmailAsync(model.Email);
                }
                else
                {
                    user = await _userManager.FindByNameAsync(model.Email);
                }

                if (user != null)
                {
                    //Check if the account has already had its email confirmed.  In this example, the account will always be confirmed, but this is here for demonstration purposes.
                    if (!user.EmailConfirmed)
                    {
                        //Check to see if the token is greater than 24 hours old
                        if ((DateTime.UtcNow - user.CreatedDate).TotalDays > 1)
                        {
                            //If it's expired we can send a new confirmation token.  Otherwise if you prefer some other approach or logic feel free to experiment!
                            await ResendConfirmationToken(user);
                            ModelState.AddModelError("", "Account Has Been Disabed By Manager. Please Contact Manager.");
                            return View(model);
                        }

                        //account hasn't been confirmed but it also hasn't been 24 hours, inform the user.  This is also a great place to present some way the user can request a new confirmation token
                        //or provide an update email address so that they can receive a new token if they had made a mistake.
                        ModelState.AddModelError("", "Account Has Been Disabed By Manager. Please Contact Manager.");
                        return View(model);
                    }
                    //string passwordh=_userManager.                    
                    //  var result = await _userManager.FindAsync(model.Email.TrimEnd(), model.Password);
                    var r = CheckSigin(model.Email.TrimEnd(), model.Password);

                    if (r == "False") {
                        ModelState.AddModelError("", "Invalid login attempt. Please enter valid registered user name.");
                        return View(model);
                    }
                    //we're good, sign the user in
                    await SignInAsync(user, model.RememberMe);

                    /* After Login */
                    var login_user = _userManager.FindById(user.Id);
                    bool Is_roaming_retainer = login_user.Is_roaming_retainer;
                    string _role = "";
                    
                    {
                        _role = login_user.default_role;
                        Session["loggedin_role"] = _role;
                    }
                   
                    Session["Role"] = _role;
                    Session["DatabaseName"] = login_user.DatabaseName;
                    if(string.IsNullOrEmpty(login_user.DatabaseName))
                    {
                      //===;
                    }
                    else
                    {
                        DbName = login_user.DatabaseName;
                    }
                    int companyid = CompanyMethods.GetCompanyByOfficeId(_userManager.FindById(user.Id).OfficeId, login_user.DatabaseName);
                    var companydetails = CompanyMethods.GetCompanyById(companyid);
                    var AddDate = companydetails.AddDate.AddDays(7);
                    var difference = DateTime.Now.Subtract(AddDate).Days;
                    if (companydetails.PlanId == 1)
                    {
                        if (difference > 2)
                        {
                            Session["Headermessage"] = "7-Day Free Trial Activated! " + difference.ToString() + " Days Left <a href='" + WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Customer/PaymentDetails/' class='btn btn-default btn-lg'>Upgrade Now</a>";
                        }
                        else
                        {
                            Session["Headermessage"] = "Your Trial is Ending Soon! Don’t Lose Access. <a href='"+ WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Customer/PaymentDetails/' class='btn btn-default btn-lg'>Upgrade Now</a>";
                        }
                    }
                    else
                    {
                        Session["Headermessage"] = "";
                    }
                    string companyname = companydetails.Name;
                    bool EnableAdmissions = companydetails.EnableAdmissions;
                    Session["CompanyId"] = companyid;
                    Session["PlanId"] = companydetails.PlanId;
                    Session["EnableAdmissions"] = EnableAdmissions;
                    Session["PaidConsultation"] = companydetails.PaidConsultation;
                    if (string.IsNullOrEmpty(companydetails.LogoUrl))
                    {
                        Session["CompanyLogo"] =  "immracio-logo.jpg";
                        Session["CompanyLogo"] = companyid.ToString() + ".jpg";
                    }
                    else
                    {
                        Session["CompanyLogo"] = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + companydetails.LogoUrl.ToString(); //=== "immracio-logo.jpg";
                    }
                    
                    if(string.IsNullOrEmpty(companyname))
                    {
                       Session["CompanyName"] = "Immracio";
                    }
                    else
                    {
                        Session["CompanyName"] = companyname;
                    }
                    Session["YearStartDate"] = companydetails.YearStartDate;
                    Session["YearEndDate"] = companydetails.YearEndDate;
                    string[] splitarray_start = companydetails.YearStartDate.ToString().Split(' ')[0].ToString().Split('/');
                    string[] splitarray_end = companydetails.YearEndDate.ToString().Split(' ')[0].ToString().Split('/');
                    string current_year_status = splitarray_start[2] + "-" + splitarray_end[2];
                    Session["YearStatus"] = ConfigurationMethods.GetYearsStatus(current_year_status, DbName);
                    string clogo = Session["CompanyLogo"].ToString();
                    string cname = Session["CompanyName"].ToString();
                    if ((_role != "Manager") && (Is_roaming_retainer == false) && (_role != "Case Coordinator"))
                    {
                        Session["Office"] = "";
                        if (_role != "Admin")
                        {
                            int office_id = _userManager.FindById(user.Id).OfficeId;
                            Session["Office"] = OfficesMethods.GetOfficeById(office_id, DbName).Name;
                        }
                    }
                    else
                    {
                        Session["Office"] = "";
                    }
                    /* After Login */
                    returnUrl = returnUrl == null ? "~/Home/Index" : returnUrl;
                    return RedirectToLocal("~/Home/Index");
                    //return RedirectToLocal(returnUrl);
                }
                ModelState.AddModelError("", "Invalid login attempt. Please enter valid registered user name.");
            }

            return View(model);
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            if (User.Identity.IsAuthenticated)
            {
                var user = User.Identity;
                if (User.IsInRole("Admin") || User.IsInRole("Manager") || User.IsInRole("Office Manager") || User.IsInRole("Processor"))
                {
                    if (User.IsInRole("Admin") || User.IsInRole("Manager"))
                    {
                        //var roleList = _roleRepository.get_all_roles().Where(x => x.Name != "Admin" && x.Name != "Prospect" && x.Name != "Client");
                        var roleList = UserMethods.get_all_roles();
                        //Not exclude Admin
                        //var roleListWithoutAdmin = roleList.Where(f => f != "Admin");
                        ViewBag.Roles = new SelectList(roleList, "Name", "Name");
                    }
                    else if (User.IsInRole("Office Manager") || User.IsInRole("Processor"))
                    {
                        var roleList = UserMethods.get_all_roles();
                        //Not exclude Admin
                        //var roleListWithoutAdmin = roleList.Where(f => f != "Admin");
                        ViewBag.Roles = new SelectList(roleList, "Name", "Name");
                    }

                    if ((UserData.GetUsersData(DbName).Role == "Manager") || (UserData.GetUsersData(DbName).Is_roaming_retainer == true))
                    {
                        int companyid = CompanyMethods.GetCompanyByOfficeId(UserData.GetUsersData(DbName).OfficeId, DbName);
                        var Offices_lst = OfficesMethods.GetAllOffice(companyid, DbName);
                        ViewBag.Offices = new SelectList(Offices_lst, "Id", "Name");
                        ViewBag.Show = "Yes";
                    }
                    else
                    {
                        ViewBag.Show = "No";
                        ViewBag.Offices = UserData.GetUsersData(DbName).OfficeId;
                    }

                    return View();
                }
            }

            var roleList1 = UserMethods.get_all_roles();
            //Not exclude Admin
            //var roleListWithoutAdmin = roleList.Where(f => f != "Admin");
            ViewBag.Roles = new SelectList(roleList1, "Name", "Name");
            
            ViewBag.Loggedinrole = UserData.GetUsersData(DbName).Role;
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [ValidateInput(false)]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model, string[] userroles1, string editor1,string cmb_default_roles, string posttype = "Save")
        {
            if (editor1 == null)
                editor1 = "";
            ViewBag.from = "Main";

            if (editor1.Length > 0)
            {
                ViewBag.from = "Agreement";
                //Post of Editor Tab
                ViewBag.editor1 = editor1;
                ViewBag.posttype = posttype;
                //Post of Tab 2 Editor
                if (User.Identity.IsAuthenticated)
                {
                    var user = User.Identity;
                    if (User.IsInRole("Admin") || User.IsInRole("Manager") || User.IsInRole("Office Manager") || User.IsInRole("Processor"))
                    {
                        if (User.IsInRole("Admin") || User.IsInRole("Manager"))
                        {
                            var roleList = UserMethods.get_all_roles();
                            ViewBag.Roles = new SelectList(roleList, "Name", "Name");
                        }
                        else if (User.IsInRole("Office Manager") || User.IsInRole("Processor"))
                        {
                            var roleList = UserMethods.get_all_roles();
                            ViewBag.Roles = new SelectList(roleList, "Name", "Name");
                        }

                        if ((UserData.GetUsersData(DbName).Role == "Manager") || (UserData.GetUsersData(DbName).Is_roaming_retainer == true))
                        {
                            int companyid = CompanyMethods.GetCompanyByOfficeId(UserData.GetUsersData(DbName).OfficeId, DbName);
                            var Offices_lst = OfficesMethods.GetAllOffice(companyid, DbName);
                            ViewBag.Offices = new SelectList(Offices_lst, "Id", "Name");
                            ViewBag.Show = "Yes";
                        }
                        else
                        {
                            ViewBag.Show = "No";
                            ViewBag.Offices = UserData.GetUsersData(DbName).OfficeId;
                        }

                        return View();
                    }
                }

                var roleList1 = UserMethods.get_all_roles();
                ViewBag.Roles = new SelectList(roleList1, "Name", "Name");
                ViewBag.Loggedinrole = UserData.GetUsersData(DbName).Role;
                return View();
            }
            else
            {
                //Post of Tab 1 Editor

                //System.Web.HttpPostedFileBase file = model.Files[0];
                if (ModelState.IsValid)
                {
                    bool isemail = false;

                    bool isadminmanger = false;

                    if (User.Identity.IsAuthenticated)
                    {
                        if (User.IsInRole("Admin") || User.IsInRole("Manager") || User.IsInRole("Office Manager") || User.IsInRole("Processor"))
                        {
                            isemail = true;
                            isadminmanger = true;
                        }
                        if (User.IsInRole("Case Coordinator"))
                        {
                            model.OfficeId = 0;
                        }
                    }
                    string p = _userManager.PasswordHasher.HashPassword(model.Password);
                    var user = new ApplicationUser { Id = Guid.NewGuid().ToString(), SecurityStamp = Guid.NewGuid().ToString(), PasswordHash = p, Email = model.Email, UserName = model.FirstName +" "+model.LastName, EmailConfirmed = isemail, PhoneNumber = model.PhoneNumber, OfficeId = model.OfficeId, FirstName = model.FirstName, LastName = model.LastName, Is_roaming_retainer = model.Is_roaming_retainer, Is_contract_owner = model.Is_contract_owner, Canoverride = model.Canoverride,default_role= cmb_default_roles,DatabaseName= DbName };
                    var result = await _userManager.CreateAsync(user, model.Password);
                    if (result.Succeeded)
                    {
                        var company_details = CompanyMethods.GetCompanyDetails_ByOfficeId(model.OfficeId, DbName);
                        string Accounttype = "";
                        bool add_account = true;
                        if (userroles1.Contains("Manager"))
                        {
                            add_account = true;
                            Accounttype = "Manager";
                        }
                        else if (userroles1.Contains("Office Manager"))
                        {
                            add_account = true;
                            Accounttype = "Office Manager";

                        }
                        else if (userroles1.Contains("Retainer"))
                        {
                            add_account = true;
                            Accounttype = "Retainer";

                        }

                        //Send Email To Agent //
                        if (userroles1.Contains("Agent"))
                        {

                            string to_body = CompanyMethods.GetTemplates_by_tag("new-agent-added", company_details.Id, DbName);
                            to_body = to_body.Replace("tag_agentname", model.FirstName + " " + model.LastName);
                            to_body = to_body.Replace("tag_companyname", company_details.Name);
                            to_body = to_body.Replace("tag_companyaddress", company_details.Address + company_details.Address1);
                            to_body = to_body.Replace("tag_username", model.Email);
                            to_body = to_body.Replace("tag_password", model.Password);


                            //to_body += "<br/><br/>Thanks.<br/>";
                            //to_body += "<br/>Customer Service<br/>" + company_details.Name + "<br/>" + company_details.Address + company_details.Address1;

                            MailMethods.SendMail(model.Email, "New Agent Added", to_body, null, new List<string> { "jonnys@nanojot.ca", "harkiratk@nanojot.com" }, null, company_details.Id, DbName);
                        }

                        if (add_account == true)
                        {
                            /* Insert into Accounts Table */
                            AccountsViewModel d1 = new AccountsViewModel();
                            d1.ReferenceId = 0;
                            d1.companyid = CompanyMethods.GetCompanyByOfficeId(model.OfficeId, DbName);
                            d1.AccountType = Accounttype + " Account";
                            d1.Name = model.FirstName + " " + model.LastName;
                            d1.str_ReferenceId = user.Id;
                            d1.officeid = model.OfficeId;
                            string startYear = Convert.ToDateTime(Session["YearStartDate"]).Year.ToString();
                            string endYear = Convert.ToDateTime(Session["YearEndDate"]).Year.ToString();
                            d1.Years = startYear + "-" + endYear;
                            ClientMethods.Insert_Account(d1, DbName);
                            /* Insert into Accounts Table */
                        }
                        if (model.City != null)
                        {
                            if (model.City.Length > 0)
                            {
                                ClientRegisterViewModel _m = new ClientRegisterViewModel();
                                _m.Address = model.Address;

                                string[] lst = model.City.Split(',');
                                _m.City = lst[0];
                                _m.Country = lst[2];
                                _m.State = lst[1];
                                _m.referenceid = user.Id;
                                ClientMethods.Insert_User_Address(_m, DbName);

                            }
                        }


                        if (isadminmanger)
                        {
                            //Assign Role to user Here      
                            foreach (var item in userroles1)
                            {
                                string roleid = UserMethods.GetRoleId_byRole(item);
                                await this._userManager.AddToRoleAsync(user.Id, roleid);
                            }


                            var roleList1 = UserMethods.get_all_roles();
                            //Not exclude Admin
                            //var roleListWithoutAdmin = roleList.Where(f => f != "Admin");
                            ViewBag.Roles = new SelectList(roleList1, "Name", "Name");
                            return RedirectToAction("Saved", "Data", new { message = "User has been created successfully", returnurl = "/Users/Index/" });
                        }
                        //==== await SignInManager.SignInAsync(user, isPersistent:true, rememberBrowser:false);

                        // Send an email with this link
                        string code = await _userManager.GenerateEmailConfirmationTokenAsync(user.Id);
                        var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                        IdentityMessage message = new IdentityMessage();
                        message.Destination = model.Email;
                        message.Subject = "Confirm your account";
                        message.Body = "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>";
                        message.Body += "<br/><br/>Thanks.<br/>";
                        message.Body += "<br/>Customer Service<br/>" + company_details.Name + "<br/>" + company_details.Address + company_details.Address1;

                        await _userManager.EmailService.SendAsync(message);
                        //Assign Role to user Here      
                        //await this.UserManager.AddToRoleAsync(user.Id, model.UserRoles);
                        foreach (var item in userroles1)
                        {
                            string roleid = UserMethods.GetRoleId_byRole(item);
                            await this._userManager.AddToRoleAsync(user.Id, roleid);
                        }

                        return RedirectToAction("Saved", "Data", new { message = "User has been created successfully", returnurl = "/Users/Index" });
                    }
                    AddErrors(result);
                }

                // If we got this far, something failed, redisplay form
                //ViewBag.Roles = new SelectList(context.Roles, "Name", "Name", model.UserRoles);
                var roleList11 = UserMethods.get_all_roles();
                //Not exclude Admin
                //var roleListWithoutAdmin = roleList.Where(f => f != "Admin");
                ViewBag.Roles = new SelectList(roleList11.ToList(), "Name", "Name");

                bool d = User.Identity.IsAuthenticated;

                string _uid = User.Identity.GetUserId();
                bool _data_user = UserMethods.GetRoamingRetainer(_uid, DbName);
                int office_current_user = UserMethods.GetCurrentUserOffice(_uid, DbName);
                if (User.IsInRole("Manager") || (_data_user == true))
                {
                    int companyid1 = CompanyMethods.GetCompanyByOfficeId(office_current_user, DbName);
                    var Offices_lst1 = OfficesMethods.GetAllOffice(companyid1, DbName);
                    ViewBag.Offices = new SelectList(Offices_lst1, "Id", "Name");
                    ViewBag.Show = "Yes";
                }
                else
                {
                    ViewBag.Show = "No";
                    ViewBag.Offices = office_current_user;
                }
                return View(model);
            }
        }


        private async Task SendConfirmationToken(ApplicationUser user)
        {
            //create a new confirmation token
            var confirmationToken = Guid.NewGuid().ToString();

            //update the users confirmation token and reset the created date
            user.ConfirmationToken = confirmationToken;
            user.CreatedDate = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            //send the new confirmation link to the user
            var callbackUrl = Url.Action("ConfirmationLink", "Account", new { id=EmailConfirmationHelper.EncodeConfirmationToken(confirmationToken,user.Email) });
            EmailConfirmationHelper.SendRegistrationEmail(confirmationToken, user.UserName, callbackUrl,DbName);
        }

        /// <summary>
        /// This is a rough example of an action result that could exist that is called from a confirmation email.  It takes the encoded ConfirmationToken object, decodes it, performs
        /// some logic to determine if the account is already confirmed, if the token expired, or if everything is ok.  This can obviously be better, but it is here for example purposes.
        /// </summary>
        /// <param name="id">In this example, if you look at EmailConfirmationHelper.DecodeConfirmationToken you will see it takes the encoded id parameter from the URL, decodes it back into
        /// the ConfirmationToken object and then uses the Email to find the user.  This is important because without this, the UserManager wouldn't have a way to actually find the user.</param>
        /// <returns></returns>
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmationLink(string id)
        {
            //decode the confirmation token
            var token = EmailConfirmationHelper.DecodeConfirmationToken(id);

            //find the user based on the email address
            var user = await _userManager.FindByNameAsync(token.Email);

            if (user != null)
            {
                //check if the user has already confirmed their account
                if (user.EmailConfirmed)
                {
                    ViewBag.MessageTitle = "Already Confirmed";
                    ViewBag.Message = "Your account is already confirmed!";
                    return View();
                }

                //check if the confirmation token is older than a day, if it is send them a new token
                if ((DateTime.UtcNow - user.CreatedDate).TotalDays > 1)
                { 
                    await ResendConfirmationToken(user);
                    ViewBag.MessageTitle = "Token Expired";
                    ViewBag.MessageTitle = "The confirmation token has expired.  A new token has been generated and emailed to you.";
                    return View();
                }

                //set the account to confirmed and updated the user
                user.EmailConfirmed = true;
                await _userManager.UpdateAsync(user);

                //pop the view to let the user know the confirmation was successful
                string code = _userManager.GeneratePasswordResetToken(user.Id);  
                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code });
                //Body11 = Body11.Replace("tag_reseturl", "<a href='" + WebConfigurationManager.AppSettings["Webapp_domain"].ToString().ToString() + code + "' target='_blank'>here</a>");
                ViewBag.MessageTitle = "Confirmation Successful";
                string message = "Your account has been successfully activated!  Click <a href='" + WebConfigurationManager.AppSettings["Webapp_domain"].ToString().ToString() + callbackUrl + "'>here</a> to Set Password.";
                ViewBag.Message = message;
                MailMethods.SendMailAdmin(user.Email, "Account Activated | Immracio", message, null, null, null, 0, DbName);
                return View();
            }

            //if we got this far then the token is completely invalid
            ViewBag.MessageTitle = "Invalid Confirmation Token";
            ViewBag.Message = "The confirmation token is invalid.  If you feel you have received this message in error, please contact [your email]";
            return View();
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword(string id)
        {
            ForgotPasswordViewModel model = new ForgotPasswordViewModel();
            model.Email = id;
            return View(model);
        }
        public ActionResult get_LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            Session.Remove("Office");
            Session.Remove("loggedin_role");
            return RedirectToAction("Login", "Account");
        }
        public async Task<string> generate_p_reset_code(string userid) {
            string code = await _userManager.GeneratePasswordResetTokenAsync(userid);
            return code;
        }
        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    ViewBag.ForgotPasswardStatus = "Failed";
                    return View("ForgotPasswordConfirmation");
                }
                ViewBag.ForgotPasswardStatus = "OK";
                // Send an email with this link
                string code = await _userManager.GeneratePasswordResetTokenAsync(user.Id);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                IdentityMessage message = new IdentityMessage();
                message.Destination = user.Email.ToString();
                message.Subject = "Reset your password";
                //message.Body = "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>";
                //await UserManager.EmailService.SendAsync(message);

                int OfficeId = UserMethods.GetUserData_byUsermail(model.Email, DbName);
                var company_details = CompanyMethods.GetCompanyDetails_ByOfficeId(OfficeId, DbName);

                string body = CompanyMethods.GetTemplates_by_tag("forgot-password", company_details.Id, DbName);
                body = body.Replace("tag_clientname", user.UserName);
                body = body.Replace("tag_reseturl", "<a href=\"" + callbackUrl + "\">here</a>");
                body = body.Replace("tag_companyname", company_details.Name);
                body = body.Replace("tag_companyaddress", company_details.Address + company_details.Address1);
                message.Body = body;
                //message.Body += "<br/><br/>Thanks.<br/>";
                //message.Body += "<br/>Customer Service<br/>" + company_details.Name + "<br/>" + company_details.Address + company_details.Address1;

                List<string> cc = new List<string>();
                if (WebConfigurationManager.AppSettings["Webapp_bcc_enable"].ToString() == "True")
                {
                    cc.Add("bhallaheemanshu@gmail.com");
                    cc.Add("harkiratk@nanojot.com");
                    cc.Add("harkiratk@nanojot.com");
                    cc.Add("jonnys@nanojot.ca");
                }
                string resp = MailMethods.SendMail(model.Email, message.Subject, message.Body, null, cc, null, company_details.Id, DbName);
                return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string userId,string code)
        {
            ResetPasswordViewModel model = new ResetPasswordViewModel();
            model.Code = code;
            model.Email = UserMethods.GetUserEmail(userId, DbName);
            return code == null ? View("Error") : View(model);
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            if (model.ConfirmPassword != model.Password)
            {
                ModelState.AddModelError("", "Password and Confirm Password must be same.");
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email.TrimEnd());
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user.Id)))
            {
                // Don't reveal that the user does not exist
                ViewBag.ForgotPasswardStatus = "Failed";
                return RedirectToAction("ResetPasswordConfirmation", "Account");

            }
            //model.Code = model.Code.Replace(" ", "+");
            var result =  _userManager.ResetPassword(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View(model);
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var user = await _userManager.FindAsync(loginInfo.Login);
            if (user != null)
            {
                await SignInAsync(user, isPersistent: false);
                return RedirectToLocal(returnUrl);
            }
            ViewBag.ReturnUrl = returnUrl;
            ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
            return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
        }

        /// <summary>
        /// If you choose to implement Google, Facebook or Twitter auth, you will need to make some slight changes to ExternalLoginConfirmationViewModel, this action and
        /// ExternalLoginConfirmation.cshtml to account  for changes to the User object including any information you want to collect.  You can use the form to gather this information
        /// or if you feel that some of this information is available to you from the source location (such as from Google) you can gather this information from claims.
        /// </summary>
        /// <param name="model"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                //here we can either use information we gathered with claims that will be contained in the info object, or we can use the data from the form - both is available to us.
                var user = new ApplicationUser { UserName = model.Email.TrimEnd(),  CreatedDate = DateTime.UtcNow, EmailConfirmed = true };
                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await _userManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInAsync(user, isPersistent: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Login", "Account");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        private async Task SignInAsync(ApplicationUser user, bool isPersistent)
        {
            //private IAuthenticationManager AuthenticationManager => HttpContext.GetOwinContext().Authentication;
        AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            var identity = await _userManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
            AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, identity);
        }

        /// <summary>
        /// This method generates a new confirmation token, updates the stored confirmation token and then sends a new confirmation email to the user.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private async Task ResendConfirmationToken(ApplicationUser user)
        {
            //create a new confirmation token
            var confirmationToken = Guid.NewGuid().ToString();

            //update the users confirmation token and reset the created date
            user.ConfirmationToken = confirmationToken;
            user.CreatedDate = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            //send the new confirmation link to the user
            //await EmailConfirmationHelper.SendRegistrationEmail(confirmationToken, user.UserName);
        }
        public ActionResult OverrideChecklist(int id, int ReferenceId, string receiptnumber,string from,string calledfrom, int SaleId=0)
        {

            ViewBag.Checklistid = id;
            ViewBag.SaleId = SaleId;
            ViewBag.ReferenceId = ReferenceId;
            ViewBag.receiptnumber = receiptnumber;
            ViewBag.from = from;
            ViewBag.calledfrom = calledfrom;
            string returnurl = "";
            int ClientId = id;
            if ((ReferenceId == 0) || (ReferenceId == -1) || (ReferenceId == -2))
            {
                if (from == "migrate_refunds") {
                    returnurl = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Migrate/Refunds/";
                }
                else
                {


                    returnurl = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Clients/Profile/" + id + "?from=refunds";
                }
            }
            else if (ReferenceId == -4)
            {

                returnurl = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Dashboard/Index/?from=cases";
            }
            else if (ReferenceId == -5)
            {
                returnurl = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Dashboard/Index/";
            }
            else
            {
                ClientId = ReferenceId;
                returnurl = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Tasks/Notes/" + ReferenceId + "/" + id + "/?SaleId="+SaleId+"Steps";

            }
            TrackingViewModel _trackmdl = new TrackingViewModel();
            _trackmdl.ClientId = ClientId;
            _trackmdl.UserId = UserData.GetUsersData(DbName).UserID;
            _trackmdl.Particulars = "override-checklist";
            int inserted = TrackingMethods.Insert(_trackmdl, DbName);
            ViewBag.inserted = inserted;
            string tracking_time_init = TrackingMethods.Get_Tracking_Time_by_ClientId(id, _trackmdl.UserId, DbName);
            ViewBag.hr = tracking_time_init.Split(':')[0];
            ViewBag.min = tracking_time_init.Split(':')[1];
            ViewBag.returnurl = returnurl;
            return View();
        }
        [HttpPost]  
        public ActionResult OverrideChecklist(LoginViewModel model1, int id, int ReferenceId, string receiptnumber,string from,string calldfrom,int SaleId)
        {
            var _clientdetails = ClientMethods.GetClientByIdNew(ReferenceId, DbName);
            string clientname = _clientdetails.FirstName + " " + _clientdetails.LastName;
            var result = CheckSigin(model1.Email, model1.Password);
            var userdetails = UserMethods.GetOverride_byemail(model1.Email, DbName);
            string Authorizedby = UserMethods.GetUID_byemail(model1.Email, DbName);
            string message = "";
            string returnurl = "";
            if ((result == "True") && (userdetails == true))
            {
                if ((ReferenceId == 0) || (ReferenceId == -4))
                {
                    //Add Refund
                    if (from == "migrate_refunds")
                    {
                        return RedirectToAction("Refund", "Migrate", new { id = id, Authorizedby = Authorizedby, referenceid = ReferenceId,SaleId=SaleId,calledfrom=calldfrom,from=from
                        });
                    }
                    else
                    {
                        return RedirectToAction("Refund", "Payments", new { id = id, Authorizedby = Authorizedby, referenceid = ReferenceId, SaleId = SaleId });
                    }
                    
                }
                else if (ReferenceId == -1)
                {
                    //Edit Refund
                    if (from == "migrate_refunds")
                    {
                        return RedirectToAction("EditRefund", "Migrate", new { ClientId = id, SaleId = SaleId, receiptnumber = receiptnumber, Authorizedby = Authorizedby, calledfrom = calldfrom, from = from });
                    }
                    else
                    {
                        return RedirectToAction("EditRefund", "Clients", new { ClientId = id, SaleId = SaleId, receiptnumber = receiptnumber, Authorizedby = Authorizedby });
                    }
                    
                }
                else if (ReferenceId == -2)
                {
                    return RedirectToAction("DeleteRefund", "Clients", new { ClientId = id, SaleId = SaleId, receiptnumber = receiptnumber,from=from, calledfrom = calldfrom });
                    //Delete Refund
                }

                else
                {

                    //User Override to Mark A Chcklist Completes

                    CheckListMethods.MarkCheckListCompleted(id, UserData.GetUsersData(DbName).UserID.ToString(), ReferenceId, UserData.GetUsersData(DbName).Name,SaleId, DbName);

                    string clientemail = ClientMethods.GetClientById(ReferenceId, DbName).Email;
                    string client_uid = UserMethods.GetUID_byemail(clientemail, DbName);

                    int Pid = CheckListMethods.GetCheckListById(id, DbName).ProductId;
                    var Applicant = ClientMethods.GetSalebyClientId(SaleId, DbName).ApplicantName;

                    //string code = UserData.resetcode(client_uid);
                    string code = _userManager.GeneratePasswordResetToken(client_uid);
                    var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = client_uid, code = code });
                    CheckListMethods.Activate_next_Checklist(id, ReferenceId, UserData.GetUsersData(DbName).UserID.ToString(), UserData.GetUsersData(DbName).Name,Applicant, callbackUrl,SaleId, DbName);

                    NotesPageViewModel model = new NotesPageViewModel();
                    model.Type = "Steps";
                    string stepname = CheckListMethods.GetCheckListById(id, DbName).Name;
                    model.Sender = UserData.GetUsersData(DbName).UserID;
                    model.Message = "Override used to complete the " + stepname + " by " + UserMethods.GetUsername_byemail(model1.Email, DbName);
                    model.ClientId = ReferenceId;
                    model.ReferenceId = id;
                    model.SaleId = SaleId;
                    NotesMethods.UpdateNotes_WithoutTask(model, DbName);


                    CheckListMethods.Save_Checklist_Override(UserMethods.GetUID_byemail(model1.Email, DbName), UserData.GetUsersData(DbName).UserID, id, ReferenceId,SaleId, DbName);

                    var company_details = CompanyMethods.GetCompanyDetails_ByOfficeId(_clientdetails.officeid, DbName);

                    string mail_message = CompanyMethods.GetTemplates_by_tag("override-checklist", company_details.Id, DbName);

                    /*mail_message += "Hi " + UserMethods.GetUsername_byemail(model1.Email) + ",<br/><br/>";
                    mail_message += "Your username and password is used to override following account. If you were the person who authorized it then you don't need to take any action otherwise please contact the user.<br/><br/>";
                    mail_message += "Client: " + clientname + "<br/>";
                    mail_message += "Product: " + ProductMethods.GetProductById(CheckListMethods.GetCheckListById(id).ProductId).ProductName + "<br/>";
                    mail_message += "Step: " + stepname + "<br/>";
                    mail_message += "User Working on: " + UserMethods.GetUsername(UserData.GetUsersData(DbName).UserID) + "<br/><br/>";
                    mail_message += "Thanks.<br/>";
                    mail_message += "<br/>Customer Service<br/>" + company_details.Name + "<br/>" + company_details.Address + company_details.Address1;
                    */

                    mail_message = mail_message.Replace("tag_username", UserMethods.GetUsername_byemail(model1.Email, DbName)); 
                    mail_message = mail_message.Replace("tag_clientname", clientname);
                    mail_message = mail_message.Replace("tag_productname", ProductMethods.GetProductById(CheckListMethods.GetCheckListById(id, DbName).ProductId, DbName).ProductName);
                    mail_message = mail_message.Replace("tag_stepname", stepname);
                    mail_message = mail_message.Replace("tag_companyname", company_details.Name);
                    mail_message = mail_message.Replace("tag_companyaddress", company_details.Address + company_details.Address1);


                    List<string> bcc = new List<string>();
                    if (WebConfigurationManager.AppSettings["Webapp_bcc_enable"].ToString() == "True")
                    {
                        bcc.Add("bhallaheemanshu@gmail.com");
                        bcc.Add("harkiratk@nanojot.com");
                        bcc.Add("harkiratk@nanojot.com");
                        bcc.Add("jonnys@nanojot.ca");
                    }
                    int compid1 = company_details.Id;
                    int NotificationSetting = NotificationMethods.Get_Notification_Settings_by_CompanyId(compid1, DbName);
                    var userid1 = UserMethods.GetUID_byemail(model1.Email, DbName);

                    if (NotificationSetting == 1)
                    {
                        /*Email*/
                        MailMethods.SendMail(model1.Email, stepname + " Completed By Override", mail_message, null, bcc, null, compid1, DbName);
                    }
                    else if (NotificationSetting == 3)
                    {
                        /*Email*/
                        MailMethods.SendMail(model1.Email, stepname + " Completed By Override", mail_message, null, bcc, null, compid1, DbName);



                        /* Notification */
                        NotificationsViewModel noti_data = new NotificationsViewModel();
                        noti_data.userid = userid1;
                        noti_data.title = stepname + " Completed By Override";
                        noti_data.content = mail_message;
                        noti_data.isread = false;
                        noti_data.notifydate = DateTime.Now;
                        NotificationMethods.save_notifications(noti_data, DbName);
                    }
                    else if (NotificationSetting == 2)
                    {
                        /* Notification */
                        NotificationsViewModel noti_data = new NotificationsViewModel();
                        noti_data.userid = userid1;
                        noti_data.title = stepname + " Completed By Override";
                        noti_data.content = mail_message;
                        noti_data.isread = false;
                        noti_data.notifydate = DateTime.Now;
                        NotificationMethods.save_notifications(noti_data, DbName);
                    }

                    //MailMethods.SendMail(model1.Email, stepname + " Completed By Override", mail_message, null, bcc, null);
                    return RedirectToAction("Notes", "Tasks", new { id = ReferenceId, ReferenceId = id, SaleId = SaleId, str = "Steps" });
                }
            }
            else
            {
                message = "You are not authorized to override";
                if ((ReferenceId == 0) || (ReferenceId == -1) || (ReferenceId == -2))
                {
                    returnurl = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Clients/Profile/" + id + "?from=refunds";
                }
                else
                {
                    returnurl = WebConfigurationManager.AppSettings["Webapp_url"].ToString() + "/Account/OverrideChecklist/" + id + "/" + ReferenceId+"?SaleId="+SaleId;

                }

            }
            return RedirectToAction("result", "Checklist", new { returnurl = returnurl, message = message });
        }
        public string CheckSigin(string username, string password)
        {
            var user = _userManager.FindByEmail(username);
            var validCredentials = _userManager.CheckPassword(user, password);
            if (validCredentials)
            {
                return "True";
            }
            else
            {
                return "False";
            }
        }

        //[HttpPost]
        //[AllowAnonymous]
        //public JsonResult AppLogin(LoginViewModel model)
        //{
        //    apploginsuccess result = new apploginsuccess();
        //    if (ModelState.IsValid)
        //    {
        //        ApplicationUser user;
        //        if (model.Email.Contains("@"))
        //        {
        //            user = _userManager.FindByEmail(model.Email);
        //        }
        //        else
        //        {
        //            user = _userManager.FindByName(model.Email);
        //        }
        //        if (user == null)
        //        {
        //            result.OfficeId = 0;
        //            result.Status = "Failure";
        //        }
        //        else
        //        {
        //            var loginresult = SignInManager.PasswordSignIn(user.UserName, model.Password, true, shouldLockout: false);
        //            var UserManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(context));
        //            var role = UserManager.GetRoles(user.Id);
        //            //string[] roleNames = Roles.GetRolesForUser();
        //            if (loginresult.ToString() != "Failure")
        //            {
        //                if (role != null)
        //                {
        //                    if (role[0].ToString() == "Reception")
        //                    {
        //                        result.OfficeId = user.OfficeId;
        //                        result.Status = "Success";
        //                    }
        //                    else
        //                    {
        //                        result.OfficeId = 0;
        //                        result.Status = "Failure";
        //                    }
        //                }
        //                else
        //                {
        //                    result.OfficeId = 0;
        //                    result.Status = "Failure";
        //                }
        //            }
        //            else
        //            {
        //                result.OfficeId = 0;
        //                result.Status = "Failure";
        //            }
        //        }
        //    }
        //    return Json(result, JsonRequestBehavior.AllowGet);
        //}

        //[HttpPost]
        [HttpGet]
        [AllowAnonymous]
        public JsonResult AppLogin1(LoginViewModel model)
        {
            apploginsuccess result = new apploginsuccess();

            result.OfficeId = 1;
            result.Status = "Success";

            return Json(result, JsonRequestBehavior.AllowGet);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _userManager?.Dispose();
            }

            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager => HttpContext.GetOwinContext().Authentication;

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }
}