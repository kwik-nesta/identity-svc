using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Suspension
{
    public record LiftSuspensionCommand : IRequest<GenericResponseDto>
    {
        public string UserId { get; set; } = string.Empty;
    }
}