using KwikNesta.Contracts.Models;
using MediatR;
using System.Text.Json.Serialization;

namespace KwikNestaIdentity.Svc.Application.Commands.PasswordRequests
{
    public record ChangeForgotPasswordCommand : IRequest<ApiResult<string>>
    {
        public string Email { get; set; } = string.Empty;
        public string Otp { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
        public string ConfirmNewPassword { get; set; } = string.Empty;
        [JsonIgnore]
        public bool PasswordMatch => 
            !string.IsNullOrWhiteSpace(NewPassword) && 
            NewPassword == ConfirmNewPassword;
    }
}
