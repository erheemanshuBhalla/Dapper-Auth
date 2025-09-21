using App.Auth.Core.Interfaces;
using App.Auth.Data.Repositories;
using App.Auth.Core.Entities;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Dapper;

namespace App.Auth.Data.Repositories
{
    public class RoleRepository:BaseRepository, IRoleRepository
    {
        public RoleRepository(IConnectionFactory connectionFactory) : base(connectionFactory)
        {
        }
        
        //Without Admin,Manager and Prospect Role
        public async  Task<List<Roles>> get_all_roles()
        {
            await WithConnection(async connection =>
            {
                var roles = await connection.QueryAsync<List<Roles>>("usp_GetAllUsers_WithRoles");
                

                return roles.ToList();
            });
            return null;


        }
        public async Task<List<Roles>> get_roles_by_userid(string userId)
        {
            return await WithConnection(async connection =>
            {
                string query = "select AspNetRoles.Id,AspNetRoles.Name from AspNetUsers join AspNetUserRoles on AspNetUsers.Id=AspNetUserRoles.UserId join AspNetRoles on AspNetRoles.Id=AspNetUserRoles.RoleId WHERE AspNetUsers.Id=@Id";
                var user = await connection.QueryAsync<Roles>(query, new { @Id = userId });
                return user.ToList();
            });
        }
        public void Dispose()
        {
        }
    }
}
