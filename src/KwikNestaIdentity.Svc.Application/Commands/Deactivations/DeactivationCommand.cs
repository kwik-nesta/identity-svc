using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Deactivations
{
    public record DeactivationCommand : IRequest<GenericResponseDto>
    {
        public string UserId { get; set; } = string.Empty;
    }
}
