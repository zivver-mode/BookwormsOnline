using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BookwormsOnline.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AesEncryptionService _crypto;

        public IndexModel(UserManager<ApplicationUser> userManager, AesEncryptionService crypto)
        {
            _userManager = userManager;
            _crypto = crypto;
        }

        public ApplicationUser? CurrentUser { get; private set; }
        public string? MaskedCreditCard { get; private set; }

        public async Task OnGetAsync()
        {
            CurrentUser = await _userManager.GetUserAsync(User);

            if (CurrentUser?.EncryptedCreditCard is { Length: > 0 })
            {
                var cc = _crypto.DecryptFromBase64(CurrentUser.EncryptedCreditCard);
                MaskedCreditCard = MaskCard(cc);
            }
        }

        private static string MaskCard(string cc)
        {
            // keep last 4 digits, mask the rest
            var digits = new string(cc.Where(char.IsDigit).ToArray());
            if (digits.Length < 4) return "****";

            var last4 = digits[^4..];
            return $"**** **** **** {last4}";
        }
    }
}
