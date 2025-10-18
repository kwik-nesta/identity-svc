using KwikNesta.Contracts.Models;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Verification
{
    public class VerificationCommand : IRequest<ApiResult<string>>
    {
        public string Otp { get; set; } = string.Empty;
        public string Email { get; set;} = string.Empty;
    }
}
