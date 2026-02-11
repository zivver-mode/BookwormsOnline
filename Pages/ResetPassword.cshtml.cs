using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using System.ComponentModel.DataAnnotations;
using System.Linq;

namespace BookwormsOnline.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly IConfiguration _config;
        private readonly RecaptchaService _recaptcha;

        public ResetPasswordModel(
            UserManager<ApplicationUser> userManager,
            AuthDbContext db,
            IConfiguration config,
            RecaptchaService recaptcha)
        {
            _userManager = userManager;
            _db = db;
            _config = config;
            _recaptcha = recaptcha;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        // Yellow info/warning (optional)
        public string? Message { get; set; }

        // Red policy/business error (invalid link, expired token, reuse old password, captcha fail)
        public string? PolicyError { get; set; }

        // Green success
        public string? SuccessMessage { get; set; }

        // Optional info (blue)
        public string? InfoMessage { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Email is required.")]
            [EmailAddress(ErrorMessage = "Please enter a valid email address.")]
            public string Email { get; set; } = "";

            [Required]
            public string Token { get; set; } = "";

            [Required(ErrorMessage = "New password is required.")]
            [DataType(DataType.Password)]
            [MinLength(12, ErrorMessage = "New password must be at least 12 characters.")]
            [Display(Name = "New password")]
            public string NewPassword { get; set; } = "";

            [Required(ErrorMessage = "Please confirm your new password.")]
            [DataType(DataType.Password)]
            [Compare(nameof(NewPassword), ErrorMessage = "New password and confirmation do not match.")]
            [Display(Name = "Confirm new password")]
            public string ConfirmNewPassword { get; set; } = "";

            // reCAPTCHA v3 token
            public string? RecaptchaToken { get; set; }
        }

        public IActionResult OnGet(string email, string token)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
            {
                PolicyError = "This reset link is invalid. Please request a new one.";
                return Page();
            }

            Input.Email = email.Trim();
            Input.Token = token;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            Input.Email = (Input.Email ?? "").Trim();

            // reCAPTCHA v3 verify (same pattern as login/register)
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
            var (ok, score, details) = await _recaptcha.VerifyAsync(Input.RecaptchaToken ?? "", "resetpassword", ip);

            if (!ok)
            {
                PolicyError = details ?? "Suspicious activity detected. Please try again.";
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                // Avoid enumeration: do not reveal whether email exists
                PolicyError = "This reset link is invalid or has expired. Please request a new one.";
                return Page();
            }

            var historyCount = int.TryParse(_config["PasswordPolicy:HistoryCount"], out var h) ? h : 2;

            // Prevent using CURRENT password again
            if (!string.IsNullOrEmpty(user.PasswordHash))
            {
                var sameAsCurrent = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, Input.NewPassword);
                if (sameAsCurrent == PasswordVerificationResult.Success)
                {
                    PolicyError = "New password must be different from your current password.";
                    return Page();
                }
            }

            // Password history check (last N)
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
                    PolicyError = $"New password cannot match your last {historyCount} passwords.";
                    return Page();
                }
            }

            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(Input.Token));
            var result = await _userManager.ResetPasswordAsync(user, decodedToken, Input.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                {
                    // Token errors -> policy banner
                    if (e.Code.Contains("InvalidToken", StringComparison.OrdinalIgnoreCase))
                    {
                        PolicyError = "This reset link is invalid or has expired. Please request a new one.";
                    }
                    // Password policy errors -> under NewPassword field
                    else if (e.Code == "PasswordTooShort" ||
                             e.Code.StartsWith("PasswordRequires", StringComparison.OrdinalIgnoreCase))
                    {
                        ModelState.AddModelError("Input.NewPassword", NormalizeIdentityPasswordError(e));
                    }
                    else
                    {
                        // Fallback: policy banner
                        PolicyError = "Unable to reset password. Please request a new reset link.";
                    }
                }

                return Page();
            }

            // Reload user AFTER reset to avoid ConcurrencyStamp mismatch
            var freshUser = await _userManager.FindByIdAsync(user.Id);
            if (freshUser == null) return RedirectToPage("/Login");

            // Store new hash after reset
            if (!string.IsNullOrEmpty(freshUser.PasswordHash))
            {
                _db.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = freshUser.Id,
                    PasswordHash = freshUser.PasswordHash,
                    CreatedAtUtc = DateTime.UtcNow
                });
            }

            // Trim to last N
            var all = await _db.PasswordHistories
                .Where(x => x.UserId == freshUser.Id)
                .OrderByDescending(x => x.CreatedAtUtc)
                .ToListAsync();

            if (all.Count > historyCount)
            {
                _db.PasswordHistories.RemoveRange(all.Skip(historyCount));
            }

            freshUser.PasswordLastChangedUtc = DateTime.UtcNow;

            try
            {
                await _userManager.UpdateAsync(freshUser);
            }
            catch (DbUpdateConcurrencyException)
            {
                // One retry (same pattern as your Login)
                freshUser = await _userManager.FindByIdAsync(user.Id);
                if (freshUser != null)
                {
                    freshUser.PasswordLastChangedUtc = DateTime.UtcNow;
                    await _userManager.UpdateAsync(freshUser);
                }
            }

            _db.AuditLogs.Add(new AuditLog
            {
                UserId = freshUser.Id,
                Email = freshUser.Email,
                Action = "RESET_PASSWORD",
                Success = true,
                Details = "Password reset successfully",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
            });

            await _db.SaveChangesAsync();

            // Match your style: show success then redirect, OR redirect immediately.
            // Minimal: show success banner and then redirect via TempData, but you asked "same as login/register".
            // So we keep redirect:
            return RedirectToPage("/Login");
        }

        private static string NormalizeIdentityPasswordError(IdentityError e)
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
    }
}
