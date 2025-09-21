using System.Text;
using System.Threading.Tasks;
using System.Web;
using App.Auth.Core.Entities;
using App.ICMS.Data.DataMethods;
using Newtonsoft.Json;

namespace App.Auth.Web.Email
{
    public class EmailConfirmationHelper
    {
        public static string EncodeConfirmationToken(string confirmationToken, string email)
        {
            var token = new ConfirmationToken
            {
                Token = confirmationToken,
                Email = email
            };

            var jsonString = JsonConvert.SerializeObject(token);
            var bytes = Encoding.UTF8.GetBytes(jsonString);
            var urlString = HttpServerUtility.UrlTokenEncode(bytes);
            return urlString;
        }

        public static ConfirmationToken DecodeConfirmationToken(string token)
        {
            var bytes = HttpServerUtility.UrlTokenDecode(token);
            var jsonString = Encoding.UTF8.GetString(bytes);
            return JsonConvert.DeserializeObject<ConfirmationToken>(jsonString);
        }

        public static  void SendRegistrationEmail(string token, string email,string callbackUrl,string Dbname)
        {
            //var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
            string message = "Email Confirmation | Immracio";
            string Subject = "Confirm your account";
            message += "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>";
            message += "<br/><br/>Thanks.<br/>";
            message += "<br/>Customer Service<br/>" + "Immracio" ;
            MailMethods.SendMailAdmin(email, Subject, message, null, null, null, 0, Dbname);
            //TODO:  Implement logic to send e-mail for confirmation if that is something you want to do
        }
    }
}