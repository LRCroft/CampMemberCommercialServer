
using campmember_commercial_webapp_linuximg.Services.HotAgency;
using CroftTeamsWinUITemplate.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ProtoBuf;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;

namespace campmember_commercial_webapp_linuximg.Pages
{

    public class PricingModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        private Model_CampCommercialWebsite_CustomerInformation customerInformationx;

        private byte[] pieceForAlter;


        public PricingModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
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


        // This method will be triggered when the form is submitted
        public async Task<IActionResult> OnPostBuyMember(int membershipType)
        {

            if (User.Identity.IsAuthenticated)
            {

                //StripeTrustedEnvironmentAgency hotStripeAgency = new StripeTrustedEnvironmentAgency(@User.FindFirst("name")?.Value);

                //string PaymentSessionURL = null; 


                //if (membershipType == 0)
                //{
                //    PaymentSessionURL = await hotStripeAgency.CreateRecurringCheckoutSession("price_1R0n9pEgetNpsvbVUQPtm4Cd", 1);
                //}
                //else if (membershipType == 1)
                //{
                //    PaymentSessionURL = await hotStripeAgency.CreateRecurringCheckoutSession("price_1R0nAnEgetNpsvbVEOBfGFnV", 1);
                //}
                //else if (membershipType == 2)
                //{
                //    PaymentSessionURL = await hotStripeAgency.CreateHotPaymentCheckoutSession("price_1Q87BMEgetNpsvbVPwgdx0vo", 1);
                //}
                //else
                //{

                //}

                //return Redirect(PaymentSessionURL);


                return null;
            }

            else
            {
                return RedirectToPage("/Login");
            }

        }


        public async Task<IActionResult> OnPostRouteToLogin()
        {
            // Redirect to the Login page
            return RedirectToPage("/Login");
        }


    }
}
