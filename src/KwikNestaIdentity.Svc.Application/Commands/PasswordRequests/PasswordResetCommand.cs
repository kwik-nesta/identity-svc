using KwikNesta.Contracts.Models;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.PasswordRequests
{
    public record PasswordResetCommand : IRequest<ApiResult<string>>
    {
        public string Email { get; set; } = string.Empty;
    }
}