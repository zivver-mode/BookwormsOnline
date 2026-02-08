using BookwormsOnline.Data;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Pages
{
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly IConfiguration _config;

        public ChangePasswordModel(UserManager<ApplicationUser> userManager, AuthDbContext db, IConfiguration config)
        {
            _userManager = userManager;
            _db = db;
            _config = config;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public string? Message { get; set; }

        public class InputModel
        {
            [Required, DataType(DataType.Password)]
            public string CurrentPassword { get; set; } = "";

            [Required, DataType(DataType.Password), MinLength(12)]
            public string NewPassword { get; set; } = "";

            [Required, DataType(DataType.Password), Compare(nameof(NewPassword))]
            public string ConfirmNewPassword { get; set; } = "";
        }

        public void OnGet(string? reason = null)
        {
            if (reason == "expired")
                Message = "Your password has expired. Please change it to continue.";
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Login");

            // Minimum password age
            var minMinutes = int.TryParse(_config["PasswordPolicy:MinChangeMinutes"], out var m) ? m : 5;
            if (DateTime.UtcNow - user.PasswordLastChangedUtc < TimeSpan.FromMinutes(minMinutes))
            {
                ModelState.AddModelError(string.Empty, $"You can change your password again after {minMinutes} minutes.");
                return Page();
            }

            // Password history check (last N)
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

            // Change password (Identity will validate complexity based on options)
            var result = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                    ModelState.AddModelError(string.Empty, e.Description);
                return Page();
            }

            // Store the NEW hash into history (keep it for future checks)
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
                Action = "CHANGE_PASSWORD",
                Success = true,
                Details = "Password changed successfully",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
            });

            await _db.SaveChangesAsync();

            return RedirectToPage("/Index");
        }
    }
}
