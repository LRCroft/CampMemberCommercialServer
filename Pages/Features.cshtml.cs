using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace campmember_commercial_webapp_linuximg.Pages
{
    public class FeaturesModel : PageModel
    {
        public FeaturesModel()
        {

        }
        public void OnGet()
        {
            // Safe to use HttpContext here
            if (HttpContext.Session.TryGetValue("ReturnUrl", out _))
            {
                HttpContext.Session.Remove("ReturnUrl");
            }
            HttpContext.Session.SetString("ReturnUrl", Url.PageLink());
        }
    }
}
