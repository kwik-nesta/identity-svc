using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.RefreshTokens
{
    public record RefreshTokenCommand : IRequest<ApiResult<RefreshTokenResponseDto>>
    {
        public string RefreshToken { get; set; } = string.Empty;
    }
}
