using KwikNesta.Contracts.Enums;
using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Verification
{
    public record ResendOtpCommand : IRequest<GenericResponseDto>
    {
        public string Email { get; set; } = string.Empty;
        public OtpType Type { get; set; }
    }
}
