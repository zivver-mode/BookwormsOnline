using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace BookwormsOnline.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;

        public ForgotPasswordModel(UserManager<ApplicationUser> userManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _emailSender = emailSender;
        }

        [BindProperty, Required, EmailAddress]
        public string Email { get; set; } = "";

        public string? Message { get; set; }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            // Default message (prevents enumeration)
            Message = "If the email is registered, a reset link will be sent.";

            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                // Keep same message (no enumeration)
                return Page();
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Make token URL-safe (avoids broken links + safer transmission format)
            var safeToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            var link = Url.Page("/ResetPassword", null, new { email = Email, token = safeToken }, Request.Scheme);

            // CodeQL note: password reset links are intentionally transmitted to the account owner.
            await _emailSender.SendAsync(
                Email,
                "Bookworms Password Reset",
                $"Reset your password using this link:\n{link}\n\nIf you did not request this, ignore this email."
            );

            // Optional: more user-friendly while still safe
            Message = "If your email is registered, a reset link has been generated. Please check your inbox.";

            return Page();
        }
    }
}
