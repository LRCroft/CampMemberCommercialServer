using Azure.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace campmember_commercial_webapp_linuximg.Pages
{

    public class IndexModel : PageModel
    {
        public bool isAuthenticated { get; set; }

        public string CustomerName { get; set; }
        public string CustomerEmail { get; set; }

        private readonly ILogger<IndexModel> _logger;
        private readonly IWebHostEnvironment _env;

        // Ensure only this constructor exists
        public IndexModel(ILogger<IndexModel> logger, IWebHostEnvironment env)
        {
            _logger = logger;
            _env = env;
        }





        public async Task OnGet()
        {
            // Seem have error ro specify the returning url with index, unlike other pages.


            if (HttpContext.Session.GetString("CacheStatus") == null)
            {
                HttpContext.Session.SetString("CacheStatus", "AlreadyClearCache");

                HttpContext.Response.Redirect("/Logout");
            }
            else
            {

            }

            // Check if the session variables are already set
            if (string.IsNullOrEmpty(HttpContext.Session.GetString("ArmDownloadUrl")) ||
                string.IsNullOrEmpty(HttpContext.Session.GetString("X64DownloadUrl")))
            {
                if (_env.IsDevelopment())
                {
                    // In development environment, use development-specific URLs
                    HttpContext.Session.SetString("ArmDownloadUrl", "TEST0");
                    HttpContext.Session.SetString("X64DownloadUrl", "TEST1");
                }
                else if (_env.IsProduction())
                {
                    HttpContext.Session.SetString("ArmDownloadUrl", "https://storage.googleapis.com/cpmwebsitesharedstorage/CPME_Windows_1.0.76.0_arm64.msix");
                    HttpContext.Session.SetString("X64DownloadUrl", "https://storage.googleapis.com/cpmwebsitesharedstorage/CPME_Windows_1.0.76.0_x64.msix");

                }
            }


            GetUserInformation();
        }

        private async Task GetUserInformation()
        {
            isAuthenticated = User.Identity.IsAuthenticated;

            if (isAuthenticated)
            {
                CustomerName = User.FindFirst("name")?.Value;
                CustomerEmail = User.FindFirst("preferred_username")?.Value;
            }
            else
            {
                Console.WriteLine("User is not authenticated.");
            }

        }









    }
}
