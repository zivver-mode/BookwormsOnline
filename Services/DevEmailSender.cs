using BookwormsOnline.Data;
using BookwormsOnline.Models;

namespace BookwormsOnline.Services
{
    public class DevEmailSender : IEmailSender
    {
        private readonly AuthDbContext _db;
        public DevEmailSender(AuthDbContext db) => _db = db;

        public async Task SendAsync(string toEmail, string subject, string body)
        {
            Console.WriteLine($"[DEV EMAIL] To={toEmail}\nSubject={subject}\nBody={body}");

            _db.AuditLogs.Add(new AuditLog
            {
                Email = toEmail,
                Action = "EMAIL",
                Success = true,
                Details = $"{subject} | {body}"
            });
            await _db.SaveChangesAsync();
        }
    }
}
