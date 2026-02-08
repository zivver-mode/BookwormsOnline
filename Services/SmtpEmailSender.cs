using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Mail;

namespace BookwormsOnline.Services
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IConfiguration _config;
        public SmtpEmailSender(IConfiguration config) => _config = config;

        public async Task SendAsync(string toEmail, string subject, string body)
        {
            var host = _config["Smtp:Host"];
            var port = int.Parse(_config["Smtp:Port"] ?? "587");
            var user = _config["Smtp:User"];
            var pass = _config["Smtp:Pass"];

            if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(pass))
                throw new InvalidOperationException("SMTP is not configured (check User Secrets).");

            using var client = new SmtpClient(host, port)
            {
                EnableSsl = true,
                Credentials = new NetworkCredential(user, pass)
            };

            using var msg = new MailMessage(user, toEmail, subject, body);

            await client.SendMailAsync(msg);
        }
    }
}
