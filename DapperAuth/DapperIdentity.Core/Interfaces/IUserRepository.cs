using App.Auth.Core.Entities;
using App.Auth.Core.ViewModels;
using Microsoft.AspNet.Identity;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace App.Auth.Core.Interfaces
{
    /// <summary>
    /// For our custom user repository, we're going to inherent the minimum required interfaces to implement identity.  There are others for more complex examples and for newer
    /// implementations we can even do all of this with claims.
    /// </summary>
    public interface IUserRepository : IUserStore<ApplicationUser>, IUserLoginStore<ApplicationUser>, IUserPasswordStore<ApplicationUser>, IUserSecurityStampStore<ApplicationUser>,IUserEmailStore<ApplicationUser>, IUserRoleStore<ApplicationUser>
    {

        Task<List<usp_GetAllUsers_WithRoles_Result>> get_users_with_roles(string userid,int? officeid,string role);
    }
}
