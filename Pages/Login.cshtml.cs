
using campmember_commercial_webapp_linuximg.Services.HotAgency;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace campmember_commercial_webapp_linuximg.Pages
{
    [Authorize]
    public class LoginModel : PageModel
    {

        private readonly ILogger<LoginModel> _logger;

        public LoginModel(ILogger<LoginModel> logger)
        {
            _logger = logger;
        }


        public async Task<IActionResult> OnGet()
        {
            return RedirectToPage("/Index");
        }
    }
}