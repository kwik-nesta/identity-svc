using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;
using System.Text.Json.Serialization;

namespace KwikNestaIdentity.Svc.Application.Commands.PasswordRequests
{
    public record ChangeForgotPasswordCommand : IRequest<GenericResponseDto>
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
