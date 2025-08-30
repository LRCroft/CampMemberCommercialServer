using campmember_commercial_webapp_linuximg.Services.HotAgency;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;
using System.Text.Json;

namespace campmember_commercial_webapp_linuximg.Pages
{
    public class FillingOurCamp : PageModel
    {
        public Dictionary<string, dynamic> Balances;
        public string ErrorMessage { get; set; }

        private readonly IWebHostEnvironment _env;

        public FillingOurCamp(IWebHostEnvironment env)
        {
            _env = env;

    //        Balances = new Dictionary<string, dynamic>
    //{
    //    { "BTC", new Dictionary<string, object> { { "balance", 10000000 }, { "balancef", 0.10000000 } } },
    //    { "ETH", new Dictionary<string, object> { { "balance", 5000000 }, { "balancef", 0.05000000 } } }
    //};
        }

        public async void OnGet()
        {
            //var coinPayments = new CoinPaymentDonationTrustedEnvironmentAgency();

            //Balances = coinPayments.CallAPI("balances", null);

            //Debug.WriteLine("TEST");


        }

    }
}
