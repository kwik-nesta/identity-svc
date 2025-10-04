using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.PasswordRequests
{
    public record PasswordResetCommand : IRequest<GenericResponseDto>
    {
        public string Email { get; set; } = string.Empty;
    }
}