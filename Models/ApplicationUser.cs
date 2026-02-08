using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required, MaxLength(50)]
        public string FirstName { get; set; } = "";

        [Required, MaxLength(50)]
        public string LastName { get; set; } = "";

        [Required, MaxLength(20)]
        public string MobileNo { get; set; } = "";

        [Required, MaxLength(200)]
        public string BillingAddress { get; set; } = "";

        // Allow special characters; Razor encodes output by default to prevent XSS
        [Required, MaxLength(200)]
        public string ShippingAddress { get; set; } = "";

        // Encrypted CC stored as Base64 string in DB
        [Required]
        public string EncryptedCreditCard { get; set; } = "";

        // Stored JPG filename under wwwroot/uploads
        [MaxLength(260)]
        public string? PhotoFileName { get; set; }

        // Used to detect multiple logins (single active session)
        [MaxLength(100)]
        public string? ActiveSessionToken { get; set; }
    }
}
