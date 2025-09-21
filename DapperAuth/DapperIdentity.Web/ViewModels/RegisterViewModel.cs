using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace App.Auth.Web.ViewModels
{
    public class RegisterViewModel
    {
        public string default_role { get; set; }
        public string City { get; set; }
        public string Address { get; set; }
        public string State { get; set; }
        public string Country { get; set; }

        [Display(Name = "User Name")]
        public string UserName { get; set; }
        [Display(Name = "First Name")]
        [Required]
        public string FirstName { get; set; }

        [Display(Name = "Last Name")]
        [Required]
        public string LastName { get; set; }

        [Phone]
        [RegularExpression(@"^[1-9]{1}[0-9]{9}", ErrorMessage = "Please enter valid 10 digit phone number.")]
        [Display(Name = "Phone Number")]
        public string PhoneNumber { get; set; }

        [EmailAddress]
        [Display(Name = "Email")]
        [Required]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [Required]
        [StringLength(100, ErrorMessage = "Your password must be more than 6 characters long, should contain at least 1 uppercase ('A'-'Z'), 1 Lowercase ('a'-'z')., 1 special character (@,#,$%__) and 1numeric ('0'-'9')", MinimumLength = 6)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Required]
        [Display(Name = "Confirm password")]
        public string ConfirmPassword { get; set; }

        [Display(Name = "UserRoles")]


        public string UserRoles { get; set; }
        [Required]
        public int OfficeId { get; set; }

        public bool Is_roaming_retainer { get; set; }
        public bool Is_contract_owner { get; set; }
        public bool Canoverride { get; set; }
        public List<System.Web.HttpPostedFileBase> Files { get; set; }
        public string agreementfile { get; set; }
    }
}
