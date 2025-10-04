using KwikNesta.Contracts.Models;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Suspension
{
    public record LiftSuspensionCommand : IRequest<ApiResult<string>>
    {
        public string UserId { get; set; } = string.Empty;
    }
}