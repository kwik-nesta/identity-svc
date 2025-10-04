using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Login
{
    public record LoginCommand : IRequest<LoginResponseDto>
    {
        public string UserName { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
