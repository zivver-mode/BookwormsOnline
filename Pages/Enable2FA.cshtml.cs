using BookwormsOnline.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BookwormsOnline.Pages
{
    [Authorize]
    public class Enable2FAModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        public string? Message { get; set; }

        public Enable2FAModel(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public void OnGet() { }

        public async Task OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) { Message = "Not logged in."; return; }

            user.TwoFactorEnabled = true;
            await _userManager.UpdateAsync(user);

            Message = "2FA enabled. Next login will require an OTP sent to your email.";
        }
    }
}
