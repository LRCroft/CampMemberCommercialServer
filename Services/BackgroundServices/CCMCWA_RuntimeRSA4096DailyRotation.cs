using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace campmember_commercial_webapp_linuximg.Services.BackgroundServices
{
    public class CCMCWA_RuntimeRSA4096DailyRotation : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Immediate key generation if none exists
            if (Program.RuntimeKeyUpdateDateTime == default)
            {
                using RSA rsa = RSA.Create(4096);
                Program.PublicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                Program.PrivateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                Program.RuntimeKeyUpdateDateTime = DateTime.Now;
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                // Regenerate if more than 24 hours passed
                if ((DateTime.Now - Program.RuntimeKeyUpdateDateTime).TotalHours >= 24)
                {
                    using RSA rsa = RSA.Create(4096);
                    Program.PublicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                    Program.PrivateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                    Program.RuntimeKeyUpdateDateTime = DateTime.Now;
                }

                // Wait 12 hours before next check
                await Task.Delay(TimeSpan.FromHours(12), stoppingToken);
            }
        }
    }
}