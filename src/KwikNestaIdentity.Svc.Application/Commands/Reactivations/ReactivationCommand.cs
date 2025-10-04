using KwikNesta.Contracts.Models;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Reactivations
{
    public record ReactivationCommand : IRequest<ApiResult<string>>
    {
        public string Email { get; set; } = string.Empty;
        public string Otp { get; set; } = string.Empty;
    }
}
