using BookwormsOnline.Data;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly IConfiguration _config;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, AuthDbContext db, IConfiguration config)
        {
            _userManager = userManager;
            _db = db;
            _config = config;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            [Required, EmailAddress]
            public string Email { get; set; } = "";

            [Required]
            public string Token { get; set; } = "";

            [Required, DataType(DataType.Password), MinLength(12)]
            public string NewPassword { get; set; } = "";

            [Required, DataType(DataType.Password), Compare(nameof(NewPassword))]
            public string ConfirmNewPassword { get; set; } = "";
        }

        public void OnGet(string email, string token)
        {
            Input.Email = email;
            Input.Token = token;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null) return RedirectToPage("/Login");

            var historyCount = int.TryParse(_config["PasswordPolicy:HistoryCount"], out var h) ? h : 2;

            var recentHashes = await _db.PasswordHistories
                .Where(x => x.UserId == user.Id)
                .OrderByDescending(x => x.CreatedAtUtc)
                .Select(x => x.PasswordHash)
                .Take(historyCount)
                .ToListAsync();

            foreach (var oldHash in recentHashes)
            {
                var verify = _userManager.PasswordHasher.VerifyHashedPassword(user, oldHash, Input.NewPassword);
                if (verify == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError(string.Empty, $"New password cannot match your last {historyCount} passwords.");
                    return Page();
                }
            }

            var result = await _userManager.ResetPasswordAsync(user, Input.Token, Input.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                    ModelState.AddModelError(string.Empty, e.Description);
                return Page();
            }

            // Store new hash after reset
            if (!string.IsNullOrEmpty(user.PasswordHash))
            {
                _db.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = user.PasswordHash,
                    CreatedAtUtc = DateTime.UtcNow
                });
            }

            // Trim to last N
            var all = await _db.PasswordHistories
                .Where(x => x.UserId == user.Id)
                .OrderByDescending(x => x.CreatedAtUtc)
                .ToListAsync();

            if (all.Count > historyCount)
            {
                var toRemove = all.Skip(historyCount);
                _db.PasswordHistories.RemoveRange(toRemove);
            }

            user.PasswordLastChangedUtc = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _db.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Email = user.Email,
                Action = "RESET_PASSWORD",
                Success = true,
                Details = "Password reset successfully",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
            });

            await _db.SaveChangesAsync();

            return RedirectToPage("/Login");
        }
    }
}
