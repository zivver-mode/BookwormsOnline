using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;

namespace BookwormsOnline.Middleware
{
    public class PasswordAgeMiddleware
    {
        private readonly RequestDelegate _next;
        public PasswordAgeMiddleware(RequestDelegate next) => _next = next;

        public async Task InvokeAsync(HttpContext context, UserManager<ApplicationUser> userManager, IConfiguration config)
        {
            if (context.User?.Identity?.IsAuthenticated == true)
            {
                var path = (context.Request.Path.Value ?? "").ToLowerInvariant();
                if (!path.StartsWith("/changepassword") &&
                    !path.StartsWith("/logout") &&
                    !path.StartsWith("/css") &&
                    !path.StartsWith("/js") &&
                    !path.StartsWith("/error"))
                {
                    var user = await userManager.GetUserAsync(context.User);
                    if (user != null)
                    {
                        // Prefer minutes if configured (useful for testing); fallback to days for backward compatibility.
                        var hasMaxMinutes = int.TryParse(config["PasswordPolicy:MaxAgeMinutes"], out var maxMinutes) && maxMinutes > 0;
                        if (hasMaxMinutes)
                        {
                            if (DateTime.UtcNow - user.PasswordLastChangedUtc > TimeSpan.FromMinutes(maxMinutes))
                            {
                                context.Response.Redirect("/ChangePassword?reason=expired");
                                return;
                            }
                        }
                        else
                        {
                            var maxAgeDays = int.TryParse(config["PasswordPolicy:MaxAgeDays"], out var d) ? d : 30;
                            if (DateTime.UtcNow - user.PasswordLastChangedUtc > TimeSpan.FromDays(maxAgeDays))
                            {
                                context.Response.Redirect("/ChangePassword?reason=expired");
                                return;
                            }
                        }
                    }
                }
            }

            await _next(context);
        }
    }
}
