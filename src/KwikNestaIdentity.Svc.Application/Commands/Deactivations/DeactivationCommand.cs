using KwikNesta.Contracts.Models;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Deactivations
{
    public record DeactivationCommand : IRequest<ApiResult<string>>
    {
        public string UserId { get; set; } = string.Empty;
    }
}
