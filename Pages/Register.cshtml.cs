using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Encodings.Web;
using System.Net;

namespace BookwormsOnline.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly AesEncryptionService _crypto;
        private readonly IWebHostEnvironment _env;
        private readonly RecaptchaService _recaptcha;

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            AuthDbContext db,
            AesEncryptionService crypto,
            IWebHostEnvironment env,
            RecaptchaService recaptcha)
        {
            _userManager = userManager;
            _db = db;
            _crypto = crypto;
            _env = env;
            _recaptcha = recaptcha;
        }
        private static string Sanitize(string? s)
        {
            // Trim + HTML encode to reduce risk of stored XSS if later rendered unsafely
            // Razor encodes by default, but this is an extra defensive layer.
            s ??= "";
            s = s.Trim();

            // HTML-encode (<, >, ", ', &) so stored values can’t execute as HTML/JS if ever output raw.
            return WebUtility.HtmlEncode(s);
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            [Required, MaxLength(50)]
            public string FirstName { get; set; } = "";

            [Required, MaxLength(50)]
            public string LastName { get; set; } = "";

            [Required, EmailAddress]
            public string Email { get; set; } = "";

            [Required]
            [RegularExpression(@"^[689]\d{7}$", ErrorMessage = "Mobile must be 8 digits and start with 6, 8, or 9.")]
            public string MobileNo { get; set; } = "";


            [Required, MaxLength(200)]
            public string BillingAddress { get; set; } = "";

            [Required, MaxLength(200)]
            public string ShippingAddress { get; set; } = "";

            [Required, RegularExpression(@"^\d{12,19}$", ErrorMessage = "Credit card must be 12–19 digits.")]
            public string CreditCard { get; set; } = "";

            [Required, DataType(DataType.Password), MinLength(12)]
            public string Password { get; set; } = "";

            [Required, DataType(DataType.Password), Compare(nameof(Password))]
            public string ConfirmPassword { get; set; } = "";

            [Required]
            public IFormFile Photo { get; set; } = default!;

            // reCAPTCHA v3 token
            public string RecaptchaToken { get; set; } = "";
        }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();
            // Defensive encoding/sanitization (stored XSS prevention)
            Input.FirstName = Sanitize(Input.FirstName);
            Input.LastName = Sanitize(Input.LastName);
            Input.Email = (Input.Email ?? "").Trim(); // keep email normal (Identity expects real email)
            Input.MobileNo = (Input.MobileNo ?? "").Trim();
            Input.BillingAddress = Sanitize(Input.BillingAddress);
            Input.ShippingAddress = Sanitize(Input.ShippingAddress);


            // reCAPTCHA v3 verify
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
            var (ok, score, details) = await _recaptcha.VerifyAsync(Input.RecaptchaToken, "register", ip);

            if (!ok)
            {
                ModelState.AddModelError(string.Empty, $"reCAPTCHA failed. {details}");
                await LogAsync(null, Input.Email, "REGISTER", false, $"reCAPTCHA failed: {details} (score {score:0.00})");
                return Page();
            }

            // Unique email check
            var existing = await _userManager.FindByEmailAsync(Input.Email);
            if (existing != null)
            {
                ModelState.AddModelError(string.Empty, "Email is already registered.");
                await LogAsync(null, Input.Email, "REGISTER", false, "Duplicate email");
                return Page();
            }

            // JPG-only validation (extension + MIME + magic bytes)
            if (!IsJpeg(Input.Photo))
            {
                ModelState.AddModelError("Input.Photo", "Photo must be a .JPG/.JPEG image.");
                await LogAsync(null, Input.Email, "REGISTER", false, "Invalid photo type");
                return Page();
            }

            // Save photo safely
            var uploadsDir = Path.Combine(_env.WebRootPath, "uploads");
            Directory.CreateDirectory(uploadsDir);

            var fileName = $"{Guid.NewGuid():N}.jpg";
            var fullPath = Path.Combine(uploadsDir, fileName);

            using (var fs = new FileStream(fullPath, FileMode.CreateNew))
            {
                await Input.Photo.CopyToAsync(fs);
            }

            // Encrypt CC before saving to DB
            var encryptedCc = _crypto.EncryptToBase64(Input.CreditCard);

            var user = new ApplicationUser
            {
                UserName = Input.Email,
                Email = Input.Email,
                FirstName = Input.FirstName,
                LastName = Input.LastName,
                MobileNo = Input.MobileNo,
                BillingAddress = Input.BillingAddress,
                ShippingAddress = Input.ShippingAddress,
                EncryptedCreditCard = encryptedCc,
                PhotoFileName = fileName
            };

            var result = await _userManager.CreateAsync(user, Input.Password);

            await LogAsync(user.Id, user.Email, "REGISTER", result.Succeeded,
                result.Succeeded ? "Success" : string.Join("; ", result.Errors.Select(e => e.Code)));

            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                    ModelState.AddModelError(string.Empty, e.Description);

                return Page();
            }

            return RedirectToPage("/Login");
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

        private static bool IsJpeg(IFormFile file)
        {
            if (file == null || file.Length == 0) return false;
            if (file.Length > 2_000_000) return false; // 2MB

            var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (ext != ".jpg" && ext != ".jpeg") return false;

            if (file.ContentType != "image/jpeg") return false;

            using var stream = file.OpenReadStream();
            if (stream.Length < 4) return false;

            // Header FF D8
            Span<byte> header = stackalloc byte[2];
            stream.Read(header);
            if (header[0] != 0xFF || header[1] != 0xD8) return false;

            // Tail FF D9
            stream.Seek(-2, SeekOrigin.End);
            Span<byte> tail = stackalloc byte[2];
            stream.Read(tail);
            return tail[0] == 0xFF && tail[1] == 0xD9;
        }
    }
}
