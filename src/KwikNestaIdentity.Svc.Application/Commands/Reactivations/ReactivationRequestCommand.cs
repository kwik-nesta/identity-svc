using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Reactivations
{
    public record ReactivationRequestCommand : IRequest<GenericResponseDto>
    {
        public string Email { get; set; } = string.Empty;
    }
}
