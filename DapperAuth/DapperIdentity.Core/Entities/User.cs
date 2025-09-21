using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNet.Identity;

namespace App.Auth.Core.Entities
{
    /// <summary>
    /// Custom fields for your user object.  Id, UserName, PasswordHash and SecurityStamp are all required by Identity.
    /// TODO:  Add your own custom fields.  Don't forget to update the database table and your SQL queries in the user repository
    /// </summary>
    public class ApplicationUser : IUser
    {
        public string default_role { get; set; }
        public string PhoneNumber { get; set; }
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public string SecurityStamp { get; set; }
        public bool EmailConfirmed { get; set; }
        public string ConfirmationToken { get; set; }
        public DateTime CreatedDate { get; set; }

        [Required]
        public int OfficeId { get; set; }
        [Required]
        public string FirstName { get; set; }

        public bool Is_roaming_retainer { get; set; }
        public bool Is_contract_owner { get; set; }
        public bool Canoverride { get; set; }

        [Required]
        public string LastName { get; set; }
        public string DatabaseName { get; set; }

        /*public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }*/


    }

    public partial class AspNetUser
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public AspNetUser()
        {
            this.AspNetUserClaims = new HashSet<AspNetUserClaim>();
            this.AspNetUserLogins = new HashSet<AspNetUserLogin>();
            this.UserAddresses = new HashSet<UserAddress>();
            this.UserProfiles = new HashSet<UserProfile>();
            this.UserCreditCardInfoes = new HashSet<UserCreditCardInfo>();
            this.AspNetRoles = new List<Roles>();
        }
        public string default_role { get; set; }
        public string City { get; set; }
        public string Address { get; set; }
        public string State { get; set; }
        public string Country { get; set; }
        public string referenceid { get; set; }

        public string Id { get; set; }
        public string Email { get; set; }
        public bool EmailConfirmed { get; set; }
        public string PasswordHash { get; set; }
        public string SecurityStamp { get; set; }
        [Display(Name = "Phone Number")]
        [RegularExpression(@"^[1-9]{1}[0-9]{9}", ErrorMessage = "Please enter valid 10 digit phone number.")]
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public Nullable<System.DateTime> LockoutEndDateUtc { get; set; }
        public bool LockoutEnabled { get; set; }
        public int AccessFailedCount { get; set; }
        [Display(Name = "User Name")]
        public string UserName { get; set; }
        [Display(Name = "User Type")]
        public string UserType { get; set; }
        
        public int OfficeId { get; set; }
        [Display(Name = "First Name")]
        public string FirstName { get; set; }
        [Display(Name = "Last Name")]
        public string LastName { get; set; }
        [Display(Name = "Is Roaming Retainer")]
        public bool Is_roaming_retainer { get; set; }
        [Display(Name = "Is Contract Owner")]
        public bool Is_contract_owner { get; set; }

        public bool Canoverride { get; set; }

        [Display(Name = "Roles")]
        public string UserRoles { get; set; }
        public string Password { get; set; }
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; }

        //public List<System.Web.HttpPostedFileBase> Files { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AspNetUserClaim> AspNetUserClaims { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AspNetUserLogin> AspNetUserLogins { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UserAddress> UserAddresses { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UserProfile> UserProfiles { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UserCreditCardInfo> UserCreditCardInfoes { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual IList<Roles> AspNetRoles { get; set; }
    }
    public partial class UserProfile
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string UserId { get; set; }
        public Nullable<long> Phone { get; set; }

        public virtual AspNetUser AspNetUser { get; set; }
    }
    public partial class UserCreditCardInfo
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string CreditCardNumber { get; set; }
        public string Name { get; set; }
        public System.DateTime ExpiryDate { get; set; }
        public int CVV { get; set; }
        public string CCBillingAddress { get; set; }
        public Nullable<long> ContactNumber { get; set; }
        public string EmailAddress { get; set; }
        public string CCType { get; set; }
        public string CCBillingCity { get; set; }
        public string CCBillingState { get; set; }
        public string CCBillingCountry { get; set; }
        public string PostalCode { get; set; }

        public virtual AspNetUser AspNetUser { get; set; }
    }
    public partial class UserAddress
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Address { get; set; }
        public string type { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Country { get; set; }
        public string zipcode { get; set; }
        public virtual AspNetUser AspNetUser { get; set; }
    }
    public partial class AspNetUserLogin
    {
        public string LoginProvider { get; set; }
        public string ProviderKey { get; set; }
        public string UserId { get; set; }

        public virtual AspNetUser AspNetUser { get; set; }
    }
    public partial class AspNetUserClaim
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string ClaimType { get; set; }
        public string ClaimValue { get; set; }

        public virtual AspNetUser AspNetUser { get; set; }
    }
    public class usp_GetAllUsers_WithRoles_Result
    {
        public string Id { get; set; }
        public int agreementid { get; set; }
        public string Email { get; set; }
        public bool EmailConfirmed { get; set; }
        public string PasswordHash { get; set; }
        public string SecurityStamp { get; set; }
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public Nullable<System.DateTime> LockoutEndDateUtc { get; set; }
        public bool LockoutEnabled { get; set; }
        public int AccessFailedCount { get; set; }
        public string UserName { get; set; }
        public string UserType { get; set; }
        public int OfficeId { get; set; }
        public string Name { get; set; }
    }
}
