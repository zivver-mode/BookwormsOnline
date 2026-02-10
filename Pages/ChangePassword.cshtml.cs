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
        [TempData]
        public string? SuccessMessage { get; set; }
        public string? PolicyError { get; set; }



        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            [Required(ErrorMessage = "Current password is required.")]
            [DataType(DataType.Password)]
            [Display(Name = "Current password")]
            public string CurrentPassword { get; set; } = "";

            [Required(ErrorMessage = "New password is required.")]
            [DataType(DataType.Password)]
            [MinLength(12, ErrorMessage = "New password must be at least 12 characters.")]
            [Display(Name = "New password")]
            public string NewPassword { get; set; } = "";

            [Required(ErrorMessage = "Please confirm your new password.")]
            [DataType(DataType.Password)]
            [Display(Name = "Confirm new password")]
            [Compare(nameof(NewPassword), ErrorMessage = "New password and confirmation do not match.")]
            public string ConfirmNewPassword { get; set; } = "";
        }

        private static string NormalizeIdentityError(IdentityError e)
        {
            return e.Code switch
            {
                "PasswordTooShort" => "New password must be at least 12 characters long.",
                "PasswordRequiresUpper" => "New password must contain at least one uppercase letter.",
                "PasswordRequiresLower" => "New password must contain at least one lowercase letter.",
                "PasswordRequiresDigit" => "New password must contain at least one number.",
                "PasswordRequiresNonAlphanumeric" => "New password must contain at least one special character.",
                _ => e.Description
            };
        }

        public void OnGet(string? reason = null)
        {
            if (reason == "expired")
            {
                PolicyError = "Your password has expired. Please change it to continue.";
            }
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
                PolicyError = $"You can change your password again after {minMinutes} minutes.";
                ClearPasswordInputs();
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

            // Also check against CURRENT password hash
            if (!string.IsNullOrEmpty(user.PasswordHash))
            {
                var sameAsCurrent = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, Input.NewPassword);
                if (sameAsCurrent == PasswordVerificationResult.Success)
                {
                    PolicyError = "New password must be different from your current password.";

                    ClearPasswordInputs();
                    return Page();
                }
            }
            // Check against last N historical hashes (your existing logic, unchanged)
            foreach (var oldHash in recentHashes)
            {
                var verify = _userManager.PasswordHasher.VerifyHashedPassword(user, oldHash, Input.NewPassword);
                if (verify == PasswordVerificationResult.Success)
                {
                    PolicyError = $"New password cannot match your last {historyCount} passwords.";

                    ClearPasswordInputs();
                    return Page();
                }
            }

            var oldHashBeforeChange = user.PasswordHash;

            // Change password (Identity validates complexity)
            var result = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                {
                    if (e.Code == "PasswordMismatch")
                    {
                        ModelState.AddModelError("Input.CurrentPassword", "Current password is incorrect.");
                    }
                    else
                    {
                        // other errors -> summary box
                        ModelState.AddModelError(string.Empty, NormalizeIdentityError(e));
                    }
                }

                ClearPasswordInputs();
                return Page();
            }

            // Store the OLD hash into history (prevents re-using it later)
            if (!string.IsNullOrEmpty(oldHashBeforeChange))
            {
                _db.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = oldHashBeforeChange,
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

            // Re-load user AFTER ChangePasswordAsync to avoid ConcurrencyStamp mismatch
            var freshUser = await _userManager.FindByIdAsync(user.Id);
            if (freshUser == null) return RedirectToPage("/Login");

            freshUser.PasswordLastChangedUtc = DateTime.UtcNow;

            try
            {
                await _userManager.UpdateAsync(freshUser);
            }
            catch (Microsoft.EntityFrameworkCore.DbUpdateConcurrencyException)
            {
                // One retry (handles rare timing/double-update)
                freshUser = await _userManager.FindByIdAsync(user.Id);
                if (freshUser == null) return RedirectToPage("/Login");

                freshUser.PasswordLastChangedUtc = DateTime.UtcNow;
                await _userManager.UpdateAsync(freshUser);
            }

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
            SuccessMessage = "Password updated successfully.";
            return RedirectToPage("/Index");

        }

        private void ClearPasswordInputs()
        {
            // You can't reliably preserve password inputs after POST (browser security),
            // so we intentionally clear them for consistency.
            Input.CurrentPassword = "";
            Input.NewPassword = "";
            Input.ConfirmNewPassword = "";
        }
    }
}
