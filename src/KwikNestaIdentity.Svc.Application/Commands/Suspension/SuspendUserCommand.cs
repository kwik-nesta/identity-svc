using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Suspension
{
    public record SuspendUserCommand : IRequest<ApiResult<string>>
    {
        public string UserId { get; set; } = string.Empty;
        public SuspensionReasons Reason { get; set; }
    }
}
