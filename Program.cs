using BookwormsOnline.Data;
using BookwormsOnline.Middleware;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.SqlServer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();

// DB
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString"))
);
builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(1);
    // Lax lets the session cookie be sent on POST->redirect, unlike Strict
    options.Cookie.SameSite = SameSiteMode.Lax;
    // Allow non-HTTPS local testing; keep Always in production
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Identity + security policy
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Strong password (server-side)
    options.Password.RequiredLength = 12;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireDigit = true;
    options.Password.RequireNonAlphanumeric = true;

    // Lockout after 3 failures
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    // Give a practical expiry so users aren't immediately signed out
    options.ExpireTimeSpan = TimeSpan.FromMinutes(1);
    options.SlidingExpiration = false;
    options.Cookie.HttpOnly = true;
    // Match session policy during development to avoid cookie rejection
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
});

builder.Services.AddScoped<AesEncryptionService>();
builder.Services.AddHttpClient();
builder.Services.AddScoped<RecaptchaService>();
builder.Services.Configure<FormOptions>(o =>
{
    o.MultipartBodyLengthLimit = 2 * 1024 * 1024; // 2MB
});
builder.Services.AddScoped<IEmailSender, SmtpEmailSender>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// 404 etc
app.UseStatusCodePagesWithReExecute("/Error/{0}");

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.UseMiddleware<BookwormsOnline.Middleware.PasswordAgeMiddleware>();

// Multiple-login detection
app.UseMiddleware<SingleSessionMiddleware>();

app.MapRazorPages();

app.Run();