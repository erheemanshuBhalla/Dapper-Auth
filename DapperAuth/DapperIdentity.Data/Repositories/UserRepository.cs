using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Dapper;
using App.Auth.Core.Entities;
using App.Auth.Core.Interfaces;
using Microsoft.AspNet.Identity;
using System.Data;

namespace App.Auth.Data.Repositories
{
    public class UserRepository : BaseRepository, IUserRepository
    {
        /// <summary>
        /// User Repository constructor passing injected connection factory to the Base Repository
        /// </summary>
        /// <param name="connectionFactory">The injected connection factory.  It is injected with the constructor argument that is the connection string.</param>
        public UserRepository(IConnectionFactory connectionFactory) : base(connectionFactory)
        {
        }

        /// <summary>
        /// INSERT operation for a new user.
        /// </summary>
        /// <param name="user">The User object must be passed in.  We create this during the Register Action.</param>
        /// <returns>Returns a 0 or 1 depending on whether operation is successful or not.</returns>
        public async Task CreateAsync(ApplicationUser user)
        {
            await WithConnection(async connection =>
            {
                /*string query = "INSERT INTO AspnetUsers(Id,UserName,Nickname,PasswordHash,SecurityStamp,IsConfirmed,ConfirmationToken,CreatedDate) VALUES(@Id,@UserName,@Nickname,@PasswordHash,@SecurityStamp,@IsConfirmed,@ConfirmationToken,@CreatedDate)";
                user.Id = Guid.NewGuid().ToString();*/
                return await connection.ExecuteAsync("usp_saveuser", new { @Id=user.Id,@Email=user.Email,@EmailConfirmed=user.EmailConfirmed, @PasswordHash=user.PasswordHash, @SecurityStamp=user.SecurityStamp, @PhoneNumber=user.PhoneNumber, @UserName=user.UserName, @OfficeId=user.OfficeId, @FirstName=user.FirstName,@LastName=user.LastName, @Is_roaming_retainer=user.Is_roaming_retainer, @Is_contract_owner=user.Is_contract_owner, @Canoverride=user.Canoverride,@default_role=user.default_role, @DatabaseName=user.DatabaseName },
                commandType: CommandType.StoredProcedure);
                //return await connection.ExecuteAsync(query, user);
            });
        }

        /// <summary>
        /// DELETE operation for a user.  This is not currently used, but required by .NET Identity.
        /// </summary>
        /// <param name="user">The User object</param>
        /// <returns>Returns a 0 or 1 depending on whether operation is successful or not.</returns>
        public async Task DeleteAsync(ApplicationUser user)
        {
            await WithConnection(async connection =>
            {
                string query = "DELETE FROM AspnetUsers WHERE Id=@Id";
                return await connection.ExecuteAsync(query, new { @Id = user.Id });
            });
        }

        /// <summary>
        /// SELECT operation for finding a user by the Id value.  Our Id is currently a GUID but this can be another data type as well.
        /// </summary>
        /// <param name="userId">The Id of the user object.</param>
        /// <returns>Returns the User object for the supplied Id or null.</returns>
        public async Task<ApplicationUser> FindByIdAsync(string userId)
        {
            return await WithConnection(async connection =>
            {
                string query = "SELECT * FROM AspnetUsers WHERE Id=@Id";
                var user = await connection.QueryAsync<ApplicationUser>(query, new { @Id = userId });
                return user.SingleOrDefault();
            });
        }
        

        /// <summary>
        /// SELECT operation for finding a user by the username.
        /// </summary>
        /// <param name="userName">The username of the user object.</param>
        /// <returns>Returns the User object for the supplied username or null.</returns>
        public async Task<ApplicationUser> FindByNameAsync(string userName)
        {
            
            return await WithConnection(async connection =>
            {
                string query = "SELECT * FROM AspnetUsers WHERE LOWER(UserName)=LOWER(@UserName)";
                var user = await connection.QueryAsync<ApplicationUser>(query, new { @UserName = userName });
                return user.SingleOrDefault();
            });
        }
        public async Task<ApplicationUser> FindByEmailAsync(string userName)
        {

            return await WithConnection(async connection =>
            {
                string query = "SELECT * FROM AspnetUsers WHERE Email=LOWER(@UserName)";
                
                var user = await connection.QueryAsync<ApplicationUser>(query, new { @UserName = userName });
                return user.SingleOrDefault();
            });
        }


        /// <summary>
        /// UPDATE operation for updating a user.
        /// </summary>
        /// <param name="user">The user that will be updated.  The updated values must be passed in to this method.</param>
        /// <returns>Returns a 0 or 1 depending on whether operation is successful or not.</returns>
        public async Task UpdateAsync(ApplicationUser user)
        {
            
            await WithConnection(async connection =>
            {

                string query =
                    "UPDATE AspnetUsers SET UserName=@UserName,PasswordHash=@PasswordHash,SecurityStamp=@SecurityStamp,EmailConfirmed=@IsConfirmed WHERE Id=@Id";
                return await connection.ExecuteAsync(query, new {@UserName=user.UserName, @PasswordHash=user.PasswordHash, @SecurityStamp=user.SecurityStamp, @IsConfirmed=user.EmailConfirmed,@Id=user.Id });
            });
        }
        public async Task ChangePasswordAsync(ApplicationUser user,string oldpass,string newpass)
        {

            await WithConnection(async connection =>
            {

                string query =
                    "UPDATE AspnetUsers SET PasswordHash=@oldpass,SecurityStamp=@SecurityStamp WHERE Id=@Id";
                return await connection.ExecuteAsync(query, new { @PasswordHash = user.PasswordHash, @SecurityStamp = user.SecurityStamp, @Id = user.Id });
            });
        }

        /// <summary>
        /// INSERT operation for adding an external login such as Google for a new or existing account.
        /// </summary>
        /// <param name="user">The User object that will be associated with the external login information.</param>
        /// <param name="login">The user login information.  This object is constructed during the callback from the external authority.</param>
        /// <returns>Returns a 0 or 1 depending on whether operation is successful or not.</returns>
        public async Task AddLoginAsync(ApplicationUser user, UserLoginInfo login)
        {
            await WithConnection(async connection =>
            {
                string query =
                    "INSERT INTO ExternalLogins(ExternalLoginId, UserId, LoginProvider, ProviderKey) VALUES(@externalLoginId, @userId, @loginProvider, @providerKey)";
                return
                    await
                        connection.ExecuteAsync(query,
                            new
                            {
                                externalLoginId = Guid.NewGuid(),
                                userId = user.Id,
                                loginProvider = login.LoginProvider,
                                providerKey = login.ProviderKey
                            });
            });
        }

        /// <summary>
        /// DELETE operation for removing an external login from an existing user account.
        /// </summary>
        /// <param name="user">The user object that the external login will be removed from.</param>
        /// <param name="login">The external login that will be removed from the user account.</param>
        /// <returns>Returns a 0 or 1 depending on whether operation is successful or not.</returns>
        public async Task RemoveLoginAsync(ApplicationUser user, UserLoginInfo login)
        {
            await WithConnection(async connection =>
            {
                string query = "DELETE FROM ExternalLogins WHERE Id = @Id AND LoginProvider = @loginProvider AND ProviderKey = @providerKey";
                return await connection.ExecuteAsync(query, new { user.Id, login.LoginProvider, login.ProviderKey });
            });
        }

        /// <summary>
        /// SELECT operation for getting external logins for a user account.
        /// </summary>
        /// <param name="user">The user account to get external login information for.</param>
        /// <returns>List of UserLoginInfo objects that contain external login information for each associated external account.</returns>
        public async Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user)
        {
            return await WithConnection(async connection =>
            {
                string query = "SELECT LoginProvider, ProviderKey FROM ExternalLogins WHERE UserId = @Id";
                var loginInfo = await connection.QueryAsync<UserLoginInfo>(query, user);
                return loginInfo.ToList();
            });
        }

        /// <summary>
        /// SELECT operation for getting the user object associated with a specific external login
        /// </summary>
        /// <param name="login">The external account</param>
        /// <returns>The User associated with the external account or null</returns>
        public async Task<ApplicationUser> FindAsync(UserLoginInfo login)
        {
            
            await WithConnection(async connection =>
            {
                string query =
                    "SELECT u.* FROM AspnetUsers u INNER JOIN ExternalLogins e ON e.UserId = u.Id WHERE e.LoginProvider = @loginProvider and e.ProviderKey = @providerKey";
                var account = await connection.QueryAsync<ApplicationUser>(query, login);
                return account.SingleOrDefault();
            });
            return null;
        }
        //RemoveFromRoles
        public async Task<ApplicationUser> RemoveFromRoles(string userid,string roleid)
        {
            await WithConnection(async connection =>
            {
                string query =
                    "delete from AspNetUserRoles where UserId=@userid and RoleId=@roleid";
                var account = await connection.QueryAsync<ApplicationUser>(query, new { @userid = userid, @roleid = roleid });
                return account.SingleOrDefault();
            });
            return null;
        }

        /// <summary>
        /// Method for setting the password hash for the user account.  This hash is used to encode the AspnetUsers password.
        /// </summary>
        /// <param name="user">The user to has the password for.</param>
        /// <param name="passwordHash">The password has to use.</param>
        /// <returns></returns>
        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        /// <summary>
        /// Method for getting teh password hash for the user account.
        /// </summary>
        /// <param name="user">The user to get the password hash for.</param>
        /// <returns>The password hash.</returns>
        public Task<string> GetPasswordHashAsync(ApplicationUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.PasswordHash);
        }

        /// <summary>
        /// Method for checking if an account has a password hash.
        /// </summary>
        /// <param name="user">The user to check for an existing password hash.</param>
        /// <returns>True of false depending on whether the password hash exists or not.</returns>
        public Task<bool> HasPasswordAsync(ApplicationUser user)
        {
            return Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));
        }
        

        /// <summary>
        /// Method for setting the security stamp for the user account.
        /// </summary>
        /// <param name="user">The user to set the security stamp for.</param>
        /// <param name="stamp">The stamp to set.</param>
        /// <returns></returns>
        public Task SetSecurityStampAsync(ApplicationUser user, string stamp)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        public Task SetEmailConfirmedAsync(ApplicationUser user, bool EmailConfirmed)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.EmailConfirmed = EmailConfirmed;
            return Task.FromResult(0);
        }

        public Task SetEmailAsync(ApplicationUser user, string Email)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.Email = Email;
            return Task.FromResult(0);
        }
        public Task<bool> IsInRoleAsync(ApplicationUser user, string role)
        {
            return Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));
        }
        public async Task AddToRoleAsync(ApplicationUser user, string role)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await WithConnection(async connection =>
            {
                string query = "insert into AspNetUserRoles(UserId,RoleId) values(@UserId,@RoleId)";
                return await connection.ExecuteAsync(query, new { @UserId = user.Id, @RoleId = role });
            });
        }
        public async Task AddToRoleAsync(string user, string role)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await WithConnection(async connection =>
            {
                string query = "insert into AspNetUserRoles(UserId,RoleId) values(@UserId,@RoleId)";
                return await connection.ExecuteAsync(query, new { @UserId = user, @RoleId = role });
            });
        }
        public async Task RemoveFromRoleAsync(ApplicationUser user, string role)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            
            await WithConnection(async connection =>
            {
                string query = "delete from AspNetUserRoles where UserId=@UserId and RoleId=@RoleId";
                return await connection.ExecuteAsync(query, new { @UserId = user.Id,RoleId=role });
            });
        }
        public async Task<IList<String>> GetRolesAsync(ApplicationUser _user)
        {
            return await WithConnection(async connection =>
            {
                string query = "select AspNetRoles.Name from AspNetUsers join AspNetUserRoles on AspNetUsers.Id=AspNetUserRoles.UserId join AspNetRoles on AspNetRoles.Id=AspNetUserRoles.RoleId WHERE AspNetUsers.Id=@Id";
                var user = await connection.QueryAsync<string>(query, new { @Id = _user.Id });
                return user.ToList();
            });
        }

        /// <summary>
        /// Method for getting the security stamp for the user account.
        /// </summary>
        /// <param name="user">The user to get the security stamp for.</param>
        /// <returns>The security stamp.</returns>
        public Task<string> GetSecurityStampAsync(ApplicationUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.SecurityStamp);
        }

        public Task<string> GetEmailAsync(ApplicationUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.Email);
        }
        public Task<bool> GetEmailConfirmedAsync(ApplicationUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.EmailConfirmed);
        }


        public async Task<List<usp_GetAllUsers_WithRoles_Result>> get_users_with_roles(string userid, int? officeid, string role)
        {
            await WithConnection(async connection =>
            {
                var user = await connection.QueryAsync<usp_GetAllUsers_WithRoles_Result>("usp_GetAllUsers_WithRoles", new { userid = userid,Officeid=officeid,role=role },
                commandType: CommandType.StoredProcedure);

                return user.ToList();
            });
            return null;
        }

        public void Dispose()
        {
        }
    }
}
