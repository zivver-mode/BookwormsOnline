using BookwormsOnline.Data;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BookwormsOnline.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;

        public LogoutModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AuthDbContext db)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user != null)
                {
                    user.ActiveSessionToken = null;
                    await _userManager.UpdateAsync(user);

                    _db.AuditLogs.Add(new AuditLog
                    {
                        UserId = user.Id,
                        Email = user.Email,
                        Action = "LOGOUT",
                        Success = true,
                        Details = "User logged out",
                        IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
                    });
                    await _db.SaveChangesAsync();
                }
            }

            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();

            return RedirectToPage("/Index");
        }
    }
}
