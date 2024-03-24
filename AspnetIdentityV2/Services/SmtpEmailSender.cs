
using AspnetIdentityV2.Models;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;

namespace AspnetIdentityV2.Services
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IOptions<SmtpOptions> _options;
        public SmtpEmailSender(IOptions<SmtpOptions> options)
        {
            _options = options;
        }
        public async Task SendEmailAsync(string from, string to, string subject, string message)
        {
            var builder = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile("appsettings.json");
            var configuration = builder.Build();
            var host = configuration["Gmail:Host"];
            var port = int.Parse(configuration["Gmail:Port"]);
            var userName = configuration["Gmail:Username"];
            var passWord = configuration["Gmail:Password"];
            var enable = bool.Parse(configuration["Gmail:SMTP:starttls:enable"]);


            var mailMessage = new MailMessage(from, to, subject, message);
            using (var client = new SmtpClient()
            {
                Host= host,
                Port= port,
                EnableSsl = enable,
                Credentials = new NetworkCredential(userName, passWord)
            })
            {
                await client.SendMailAsync(mailMessage);
            }
        }
    }
}
