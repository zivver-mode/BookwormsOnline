using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [MaxLength(256)]
        public string? UserId { get; set; }

        [MaxLength(256)]
        public string? Email { get; set; }

        [Required, MaxLength(50)]
        public string Action { get; set; } = ""; // REGISTER / LOGIN / LOGOUT

        public bool Success { get; set; }

        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

        [MaxLength(64)]
        public string? IpAddress { get; set; }

        [MaxLength(400)]
        public string? Details { get; set; }
    }
}
