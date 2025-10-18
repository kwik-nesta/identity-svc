using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.UpdateBasicDetails
{
    public record UpdateBasicUserDetailsCommand : IRequest<ApiResult<string>>
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? OtherName { get; set; }
        public Gender Gender { get; set; }
    }
}
