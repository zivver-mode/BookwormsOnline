using BookwormsOnline.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QRCoder;
using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;

namespace BookwormsOnline.Pages
{
    [Authorize]
    public class Enable2FAModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly UrlEncoder _urlEncoder;

        public Enable2FAModel(UserManager<ApplicationUser> userManager, UrlEncoder urlEncoder)
        {
            _userManager = userManager;
            _urlEncoder = urlEncoder;
        }

        public bool IsEnabled { get; set; }
        public string SharedKey { get; set; } = "";
        public string QrCodeImageUrl { get; set; } = "";
        public string? Message { get; set; }

        [BindProperty]
        [Required]
        public string VerificationCode { get; set; } = "";

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Login");

            IsEnabled = await _userManager.GetTwoFactorEnabledAsync(user);

            if (!IsEnabled)
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                await LoadSharedKeyAndQrAsync(user);
            }

            return Page();
        }

        public async Task<IActionResult> OnPostEnableAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Login");

            IsEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            if (IsEnabled)
            {
                Message = "2FA is already enabled.";
                return RedirectToPage();
            }

            if (!ModelState.IsValid)
            {
                await LoadSharedKeyAndQrAsync(user);
                return Page();
            }

            // Normalize input (spaces/hyphens)
            var code = VerificationCode.Replace(" ", "").Replace("-", "");

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                code);

            if (!isValid)
            {
                ModelState.AddModelError(string.Empty, "Invalid verification code.");
                await LoadSharedKeyAndQrAsync(user);
                return Page();
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            Message = "Two-factor authentication is now enabled.";

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDisableAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Login");

            await _userManager.SetTwoFactorEnabledAsync(user, false);

            // Optional: reset key so re-enabling requires new setup
            await _userManager.ResetAuthenticatorKeyAsync(user);

            Message = "Two-factor authentication has been disabled.";
            return RedirectToPage();
        }

        private async Task LoadSharedKeyAndQrAsync(ApplicationUser user)
        {
            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            SharedKey = FormatKey(key!);

            var email = user.Email ?? user.UserName ?? "user";
            var otpauthUrl =
                $"otpauth://totp/{_urlEncoder.Encode("BookwormsOnline")}:{_urlEncoder.Encode(email)}" +
                $"?secret={key}&issuer={_urlEncoder.Encode("BookwormsOnline")}&digits=6";

            QrCodeImageUrl = GenerateQrCodeDataUrl(otpauthUrl);
        }

        private static string FormatKey(string key)
        {
            // group into 4s for readability
            return string.Join(" ", Enumerable.Range(0, (key.Length + 3) / 4)
                .Select(i => key.Substring(i * 4, Math.Min(4, key.Length - i * 4))));
        }

        private static string GenerateQrCodeDataUrl(string text)
        {
            using var qrGenerator = new QRCodeGenerator();
            using var qrData = qrGenerator.CreateQrCode(text, QRCodeGenerator.ECCLevel.Q);
            var qrCode = new PngByteQRCode(qrData);
            var pngBytes = qrCode.GetGraphic(10);
            return "data:image/png;base64," + Convert.ToBase64String(pngBytes);
        }
    }
}
