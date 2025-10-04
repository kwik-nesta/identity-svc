using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.RefreshTokens
{
    public record RefreshTokenCommand : IRequest<RefreshTokenResponseDto>
    {
        public string RefreshToken { get; set; } = string.Empty;
    }
}
