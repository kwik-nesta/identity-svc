using KwikNesta.Contracts.Models;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Reactivations
{
    public record ReactivationRequestCommand : IRequest<ApiResult<string>>
    {
        public string Email { get; set; } = string.Empty;
    }
}
