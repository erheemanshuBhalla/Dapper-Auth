using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace App.Auth.Core.ViewModels
{
    public class UserDataViewModel
    {
        public string UserID { get; set; }
        public string Role { get; set; }
        public bool Is_Authenticated { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public int OfficeId { get; set; }
        public bool Is_roaming_retainer { get; set; }
    }

    public class apploginsuccess
    {
        public int OfficeId { get; set; }
        public string Status { get; set; }
    }
}
