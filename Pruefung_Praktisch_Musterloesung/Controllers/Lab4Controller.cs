using System;
using System.Web.Mvc;
using System.Linq;
using System.Web;
using System.Security.Cryptography;
using System.Text;
using Pruefung_Praktisch_Musterloesung.Models;

namespace Pruefung_Praktisch_Musterloesung.Controllers
{
    public class Lab4Controller : Controller
    {

        /**
        * 
        * ANTWORTEN BITTE HIER
        * According to the logs, Ip address can be blocked before user verifies the access. -> Prevent e.g. Phishing, XSS ...
        * */

        public ActionResult Index() {

            Lab4IntrusionLog model = new Lab4IntrusionLog();
            return View(model.getAllData());   
        }

        private bool VerifyEmail(string username)
        {
            bool verified = false;
            try
            {
                var addr = new System.Net.Mail.MailAddress(username);
                verified = addr.Address == username;
            }
            catch
            {
                verified = false;
            }

            char[] smallAndAt = { '@', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

            if (!username.All(u => smallAndAt.Contains(u)))
            {
                verified = false;
            }

            return verified;
        }

        private bool VerifyPassword(string password)
        {
            char[] small = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            char[] big = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };

            return password.Length >= 10 && password.Length <= 20 && password.Any(p => small.Contains(p)) && password.Any(p => big.Contains(p));
        }

        [HttpPost]
        public ActionResult Login()
        {
            var username = Request["username"];
            var password = Request["password"];
            
            if (!VerifyEmail(username))
            {
                ModelState.AddModelError("Username", "Username is not in email-format");
            }

            if (!VerifyPassword(password))
            {
                ModelState.AddModelError("Password", "Password should be 10~20 characters long and contain Capital, number");
            }

            bool intrusion_detected = false;

            var browser = Request.Browser.Platform;
            var ip = Request.UserHostAddress;

            Lab4IntrusionLog model = new Lab4IntrusionLog();

            if (model.getAllData().Any(d => d[0] != ip && d[1] != browser))
            {
                model.logIntrusion(ip, browser, "Foreign Ip, Browser used.");
                intrusion_detected = true;
            }
            

            if (intrusion_detected)
            {
                return RedirectToAction("Index", "Lab4");
            }
            else
            {
                // check username and password
                // this does not have to be implemented!
                return RedirectToAction("Index", "Lab4");
            }
        }
    }
}