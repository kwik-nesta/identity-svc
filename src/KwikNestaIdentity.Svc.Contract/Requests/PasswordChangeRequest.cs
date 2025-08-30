using System.Text.Json.Serialization;

namespace KwikNestaIdentity.Svc.Contract.Requests
{
    public class PasswordChangeRequest
    {
        public string CurrentPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
        public string ConfirmNewPassword { get; set; } = string.Empty;

        [JsonIgnore]
        public bool IsValid => !string.IsNullOrWhiteSpace(CurrentPassword) &&
            !string.IsNullOrWhiteSpace(NewPassword) && !string.IsNullOrWhiteSpace(ConfirmNewPassword) &&
            NewPassword.Equals(ConfirmNewPassword);
    }
}
