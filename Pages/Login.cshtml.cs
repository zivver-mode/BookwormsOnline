using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly RecaptchaService _recaptcha;

        public LoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AuthDbContext db,
            RecaptchaService recaptcha)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
            _recaptcha = recaptcha;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        // Yellow info/warning message (session expired etc.)
        public string? Message { get; set; }

        // Red policy/business error message (invalid login / locked out etc.)
        public string? PolicyError { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Email is required.")]
            [EmailAddress(ErrorMessage = "Please enter a valid email address.")]
            [Display(Name = "Email")]
            public string Email { get; set; } = "";

            [Required(ErrorMessage = "Password is required.")]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; } = "";

            public bool RememberMe { get; set; }
            public string? RecaptchaToken { get; set; }

        }

        public void OnGet(string? reason = null)
        {
            if (reason == "session")
                Message = "Your session expired or you signed in from another device. Please log in again.";
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();
            var (ok, score, error) = await _recaptcha.VerifyAsync(
                Input.RecaptchaToken ?? "",
                expectedAction: "login",
                remoteIp: HttpContext.Connection.RemoteIpAddress?.ToString()
            );

            if (!ok)
            {
                PolicyError = error ?? "Suspicious activity detected. Please try again.";
                return Page();
            }


            // Normalize common input mistakes
            Input.Email = (Input.Email ?? "").Trim();

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                await LogAsync(null, Input.Email, "LOGIN", false, "Unknown email");
                PolicyError = "Invalid login attempt.";
                return Page();
            }

            // IMPORTANT: lockoutOnFailure must be true (assignment lockout after 3)
            var result = await _signInManager.PasswordSignInAsync(
                user.UserName!,
                Input.Password,
                Input.RememberMe,
                lockoutOnFailure: true);

            if (result.Succeeded)
            {
                // Re-load user AFTER sign-in to avoid ConcurrencyStamp mismatch
                var freshUser = await _userManager.FindByIdAsync(user.Id);
                if (freshUser == null)
                {
                    await LogAsync(null, Input.Email, "LOGIN", false, "User missing after sign-in");
                    PolicyError = "Invalid login attempt.";
                    return Page();
                }

                var token = Guid.NewGuid().ToString("N");
                freshUser.ActiveSessionToken = token;

                try
                {
                    await _userManager.UpdateAsync(freshUser);
                }
                catch (Microsoft.EntityFrameworkCore.DbUpdateConcurrencyException)
                {
                    // One retry (handles rare double-update timing)
                    freshUser = await _userManager.FindByIdAsync(user.Id);
                    if (freshUser == null)
                    {
                        PolicyError = "Invalid login attempt.";
                        return Page();
                    }

                    freshUser.ActiveSessionToken = token;
                    await _userManager.UpdateAsync(freshUser);
                }

                HttpContext.Session.SetString("SessionToken", token);

                await LogAsync(freshUser.Id, freshUser.Email, "LOGIN", true, "Success");

                return RedirectToPage("/Index");
            }

            if (result.RequiresTwoFactor)
            {
                return RedirectToPage("/Login2FA", new { email = Input.Email, rememberMe = Input.RememberMe });
            }

            if (result.IsLockedOut)
            {
                await LogAsync(user.Id, user.Email, "LOGIN", false, "Locked out");
                PolicyError = "Account locked due to multiple failed attempts. Try again later.";
                return Page();
            }

            await LogAsync(user.Id, user.Email, "LOGIN", false, "Bad password");
            PolicyError = "Invalid login attempt.";
            return Page();
        }

        private async Task LogAsync(string? userId, string? email, string action, bool success, string details)
        {
            _db.AuditLogs.Add(new AuditLog
            {
                UserId = userId,
                Email = email,
                Action = action,
                Success = success,
                Details = details,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
            });
            await _db.SaveChangesAsync();
        }
    }
}
