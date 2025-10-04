using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.PasswordRequests
{
    public record ChangePasswordCommand : IRequest<GenericResponseDto>
    {
        public string CurrentPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
        public string ConfirmNewPassword { get; set; } = string.Empty;
    }
}
