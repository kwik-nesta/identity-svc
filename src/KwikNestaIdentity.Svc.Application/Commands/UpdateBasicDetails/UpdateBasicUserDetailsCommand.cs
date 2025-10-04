using KwikNesta.Contracts.Enums;
using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.UpdateBasicDetails
{
    public record UpdateBasicUserDetailsCommand : IRequest<GenericResponseDto>
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? OtherName { get; set; }
        public Gender Gender { get; set; }
    }
}
