using BookwormsOnline.Models;
using System.Text.Json;

namespace BookwormsOnline.Services
{
    public class RecaptchaService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _config;

        public RecaptchaService(IHttpClientFactory httpClientFactory, IConfiguration config)
        {
            _httpClientFactory = httpClientFactory;
            _config = config;
        }

        public async Task<(bool Ok, double Score, string Details)> VerifyAsync(string token, string expectedAction, string remoteIp)
        {
            var secret = _config["Recaptcha:SecretKey"];
            if (string.IsNullOrWhiteSpace(secret))
                return (false, 0, "Recaptcha secret key missing");

            var minScoreStr = _config["Recaptcha:MinScore"];
            _ = double.TryParse(minScoreStr, out var minScore);
            if (minScore <= 0) minScore = 0.5;

            var client = _httpClientFactory.CreateClient();

            var form = new Dictionary<string, string>
            {
                ["secret"] = secret,
                ["response"] = token
            };

            // remoteip is optional, but good for auditing
            if (!string.IsNullOrWhiteSpace(remoteIp))
                form["remoteip"] = remoteIp;

            using var content = new FormUrlEncodedContent(form);
            using var resp = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            if (!resp.IsSuccessStatusCode)
                return (false, 0, $"Recaptcha HTTP {(int)resp.StatusCode}");

            var json = await resp.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<RecaptchaVerifyResponse>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (result == null)
                return (false, 0, "Recaptcha invalid response");

            if (!result.Success)
                return (false, result.Score, "Recaptcha failed: " + string.Join(",", result.ErrorCodes ?? Array.Empty<string>()));

            // Action check prevents token reuse across pages
            if (!string.Equals(result.Action, expectedAction, StringComparison.OrdinalIgnoreCase))
                return (false, result.Score, $"Bad action: {result.Action}");

            if (result.Score < minScore)
                return (false, result.Score, $"Low score: {result.Score:0.00}");

            return (true, result.Score, "OK");
        }
    }
}
