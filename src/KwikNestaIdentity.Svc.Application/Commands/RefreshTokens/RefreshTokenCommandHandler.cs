using API.Common.Response.Model.Exceptions;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNesta.Contracts.Enums;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace KwikNestaIdentity.Svc.Application.Commands.RefreshTokens
{
    public class RefreshTokenCommandHandler : IRequestHandler<RefreshTokenCommand, RefreshTokenResponseDto>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEFCoreCrudKit _crudKit;
        private readonly Jwt _configs;

        public RefreshTokenCommandHandler(UserManager<AppUser> userManager,
                                          IOptions<Jwt> options,
                                          IEFCoreCrudKit crudKit)
        {
            _userManager = userManager;
            _crudKit = crudKit;
            _configs = options.Value;
        }

        public async Task<RefreshTokenResponseDto> Handle(RefreshTokenCommand request, CancellationToken cancellationToken)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.RefreshToken))
            {
                throw new BadRequestException("Invalid refresh token");
            }

            var storedToken = await ValidateRefreshTokenAsync(request.RefreshToken) ??
                throw new ForbiddenException("Invalid or expired token");

            var user = await _userManager.FindByIdAsync(storedToken.UserId) ??
                throw new NotFoundException("User not found");

            if (user.Status != UserStatus.Active)
            {
                throw new ForbiddenException("User is inactive. Please reactivate your account to continue.");
            }

            // generate new tokens
            var roles = (await _userManager.GetRolesAsync(user)).ToArray();
            var newAccessToken = AuthHelpers.CreateAccessToken(user, roles, _configs);
            return new RefreshTokenResponseDto(newAccessToken, request.RefreshToken);
        }

        #region Private Methods
        private async Task<RefreshToken?> ValidateRefreshTokenAsync(string token)
        {
            var hash = AuthHelpers.ComputeHash(token);
            var rec = await _crudKit.AsQueryable<RefreshToken>(r => r.TokenHash == hash && r.ClientId == _configs.ClientId, false)
                .FirstOrDefaultAsync();

            if (rec == null || rec.RevokedAt != null)
            {
                return null;
            }
            if (rec.ExpiresAt < DateTimeOffset.UtcNow)
            {
                rec.RevokedAt = DateTimeOffset.UtcNow;
                rec.IsDeprecated = true;
                await _crudKit.UpdateAsync(rec);
                return null;
            }
            return rec;
        }
        #endregion
    }
}
