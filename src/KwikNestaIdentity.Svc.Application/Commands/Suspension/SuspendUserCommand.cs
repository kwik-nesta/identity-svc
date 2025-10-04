using KwikNesta.Contracts.Enums;
using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Suspension
{
    public record SuspendUserCommand : IRequest<GenericResponseDto>
    {
        public string UserId { get; set; } = string.Empty;
        public SuspensionReasons Reason { get; set; }
    }
}
