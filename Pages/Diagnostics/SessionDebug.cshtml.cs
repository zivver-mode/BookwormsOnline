using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BookwormsOnline.Pages.Diagnostics
{
    [AllowAnonymous]
    public class SessionDebugModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        public SessionDebugModel(UserManager<ApplicationUser> userManager) => _userManager = userManager;

        [BindProperty(SupportsGet = true)]
        public string? Email { get; set; }

        public DateTime ServerUtcNow { get; private set; }
        public bool IsHttps { get; private set; }
        public Dictionary<string, string?> RequestCookies { get; private set; } = new();
        public string? SessionToken { get; private set; }
        public bool SessionReadWriteOk { get; private set; }
        public string? SessionError { get; private set; }
        public string? ActiveSessionToken { get; private set; }
        public bool UserFound { get; private set; }

        public async Task<IActionResult> OnGetAsync()
        {
            ServerUtcNow = DateTime.UtcNow;
            IsHttps = HttpContext.Request.IsHttps;

            foreach (var kv in HttpContext.Request.Cookies)
                RequestCookies[kv.Key] = kv.Value;

            try
            {
                HttpContext.Session.SetString("DiagTest", Guid.NewGuid().ToString("N"));
                var v = HttpContext.Session.GetString("DiagTest");
                SessionReadWriteOk = v != null;
            }
            catch (Exception ex)
            {
                SessionReadWriteOk = false;
                SessionError = ex.ToString();
            }

            SessionToken = HttpContext.Session.GetString("SessionToken");

            if (!string.IsNullOrWhiteSpace(Email))
            {
                var user = await _userManager.FindByEmailAsync(Email.Trim());
                if (user != null)
                {
                    UserFound = true;
                    ActiveSessionToken = user.ActiveSessionToken;
                }
            }

            return Page();
        }
    }
}