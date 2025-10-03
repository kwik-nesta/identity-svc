using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Verification
{
    public class VerificationCommand : IRequest<GenericResponseDto>
    {
        public string Otp { get; set; } = string.Empty;
        public string Email { get; set;} = string.Empty;
    }
}
