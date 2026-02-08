using System.Text.Json.Serialization;

namespace BookwormsOnline.Models
{
    public class RecaptchaVerifyResponse
    {
        public bool Success { get; set; }
        public double Score { get; set; }
        public string Action { get; set; } = "";
        public string Hostname { get; set; } = "";
        public DateTime ChallengeTs { get; set; }

        [JsonPropertyName("error-codes")]
        public string[]? ErrorCodes { get; set; }
    }
}
