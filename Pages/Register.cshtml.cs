using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly AesEncryptionService _crypto;
        private readonly IWebHostEnvironment _env;

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            AuthDbContext db,
            AesEncryptionService crypto,
            IWebHostEnvironment env)
        {
            _userManager = userManager;
            _db = db;
            _crypto = crypto;
            _env = env;
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

            [Required, MaxLength(20)]
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
        }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            // Unique email check (assignment requirement)
            var existing = await _userManager.FindByEmailAsync(Input.Email);
            if (existing != null)
            {
                ModelState.AddModelError(string.Empty, "Email is already registered.");
                return Page();
            }

            // JPG-only validation
            if (!IsJpeg(Input.Photo))
            {
                ModelState.AddModelError("Input.Photo", "Photo must be a .JPG/.JPEG image.");
                return Page();
            }

            // Save photo
            var uploads = Path.Combine(_env.WebRootPath, "uploads");
            Directory.CreateDirectory(uploads);
            var fileName = $"{Guid.NewGuid():N}.jpg";
            var fullPath = Path.Combine(uploads, fileName);

            using (var fs = new FileStream(fullPath, FileMode.Create))
            {
                await Input.Photo.CopyToAsync(fs);
            }

            // Encrypt credit card before saving
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

            // Audit log (success/failure)
            _db.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Email = Input.Email,
                Action = "REGISTER",
                Success = result.Succeeded,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
            });
            await _db.SaveChangesAsync();

            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                    ModelState.AddModelError(string.Empty, e.Description);

                return Page();
            }

            return RedirectToPage("/Login");
        }

        private static bool IsJpeg(IFormFile file)
        {
            var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (ext != ".jpg" && ext != ".jpeg") return false;
            if (file.ContentType != "image/jpeg") return false;

            // Magic bytes check: FF D8 ... FF D9
            using var stream = file.OpenReadStream();
            if (stream.Length < 4) return false;

            Span<byte> header = stackalloc byte[2];
            stream.Read(header);
            if (header[0] != 0xFF || header[1] != 0xD8) return false;

            stream.Seek(-2, SeekOrigin.End);
            Span<byte> tail = stackalloc byte[2];
            stream.Read(tail);
            return tail[0] == 0xFF && tail[1] == 0xD9;
        }
    }
}
