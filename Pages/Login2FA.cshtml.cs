using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Pages
{
    public class Login2FAModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly IEmailSender _emailSender;

        public Login2FAModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AuthDbContext db,
            IEmailSender emailSender)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
            _emailSender = emailSender;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            [Required, EmailAddress]
            public string Email { get; set; } = "";

            public bool RememberMe { get; set; }

            [Required]
            public string Code { get; set; } = "";
        }

        public async Task<IActionResult> OnGetAsync(string email, bool rememberMe)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return RedirectToPage("/Login");

            // Send OTP via Identity email token provider
            var code = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            await _emailSender.SendAsync(email, "Bookworms OTP", $"Your OTP code is: {code}");

            Input.Email = email;
            Input.RememberMe = rememberMe;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null) return RedirectToPage("/Login");

            var result = await _signInManager.TwoFactorSignInAsync(
                TokenOptions.DefaultEmailProvider,
                Input.Code,
                Input.RememberMe,
                rememberClient: false);

            if (result.Succeeded)
            {
                // IMPORTANT: set session token for single-session middleware
                var token = Guid.NewGuid().ToString("N");
                user.ActiveSessionToken = token;
                await _userManager.UpdateAsync(user);
                HttpContext.Session.SetString("SessionToken", token);

                _db.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Email = user.Email,
                    Action = "LOGIN_2FA",
                    Success = true,
                    Details = "2FA success",
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
                });
                await _db.SaveChangesAsync();

                return RedirectToPage("/Index");
            }

            _db.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Email = user.Email,
                Action = "LOGIN_2FA",
                Success = false,
                Details = "2FA failed",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
            });
            await _db.SaveChangesAsync();

            ModelState.AddModelError(string.Empty, "Invalid OTP code.");
            return Page();
        }
    }
}
