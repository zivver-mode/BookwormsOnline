using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;

namespace BookwormsOnline.Middleware
{
    public class SingleSessionMiddleware
    {
        private readonly RequestDelegate _next;
        public SingleSessionMiddleware(RequestDelegate next) => _next = next;

        public async Task InvokeAsync(
            HttpContext context,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            if (context.User?.Identity?.IsAuthenticated == true)
            {
                var path = (context.Request.Path.Value ?? "").ToLowerInvariant();

                // Avoid loops for auth pages and static files
                if (!path.StartsWith("/login") &&
                    !path.StartsWith("/register") &&
                    !path.StartsWith("/logout") &&
                    !path.StartsWith("/css") &&
                    !path.StartsWith("/js") &&
                    !path.StartsWith("/lib") &&
                    !path.StartsWith("/error"))
                {
                    var user = await userManager.GetUserAsync(context.User);
                    if (user != null)
                    {
                        var sessionToken = context.Session.GetString("SessionToken");

                        if (string.IsNullOrEmpty(sessionToken) ||
                            string.IsNullOrEmpty(user.ActiveSessionToken) ||
                            sessionToken != user.ActiveSessionToken)
                        {
                            await signInManager.SignOutAsync();
                            context.Session.Clear();
                            context.Response.Redirect("/Login?reason=session");
                            return;
                        }
                    }
                }
            }

            await _next(context);
        }
    }
}
