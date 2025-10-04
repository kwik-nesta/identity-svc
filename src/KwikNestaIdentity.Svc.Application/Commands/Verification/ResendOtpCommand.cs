using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Verification
{
    public record ResendOtpCommand : IRequest<ApiResult<string>>
    {
        public string Email { get; set; } = string.Empty;
        public OtpType Type { get; set; }
    }
}
