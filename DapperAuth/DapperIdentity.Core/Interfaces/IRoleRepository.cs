using App.Auth.Core.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace App.Auth.Core.Interfaces
{
    public interface IRoleRepository
    {
        //Without Admin,Manager and Client
        Task<List<Roles>> get_all_roles();

        Task<List<Roles>> get_roles_by_userid(string UserId);
    }
}
