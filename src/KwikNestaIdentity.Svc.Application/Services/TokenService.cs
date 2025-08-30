using API.Common.Response.Model.Responses;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNestaIdentity.Svc.Application.Services.Interfaces;
using KwikNestaIdentity.Svc.Contract.Requests;
using KwikNestaIdentity.Svc.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace KwikNestaIdentity.Svc.Application.Services
{
    public class TokenService : ITokenService
    {
        private readonly IEFCoreCrudKit _db;
        private readonly UserManager<AppUser> _userManager;
        private readonly Jwt _config;

        public TokenService(IEFCoreCrudKit db, IOptions<Jwt> config, UserManager<AppUser> userManager)
        {
            _db = db;
            _userManager = userManager;
            _config = config.Value;
        }

        public string CreateAccessToken(AppUser user, string[] roles, string validAudience)
        {
            var claims = GetClaims(user, roles);
            var creds = GetSigningCredentials();
            var jwt = GetJwtSecurityToken(claims, creds, DateTime.UtcNow, validAudience);

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        public async Task<string> CreateAndSaveRefreshTokenAsync(string userId)
        {
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            var hash = ComputeHash(token);
            var record = new RefreshToken
            {
                Id = Guid.NewGuid(),
                TokenHash = hash,
                UserId = userId,
                ClientId = _config.ClientId,
                ExpiresAt = DateTimeOffset.UtcNow.Add(TimeSpan.FromDays(_config.Span))
            };

            await _db.InsertAsync(record);
            return token;
        }

        public async Task<ApiBaseResponse> RefreshTokenAsync(RefreshTokenRequest request, string validAudience)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.RefreshToken))
            {
                return new UnauthorizedResponse("Invalid refresh token");
            }

            var storedToken = await ValidateRefreshTokenAsync(request.RefreshToken);
            if (storedToken == null)
            {
                return new UnauthorizedResponse("Invalid or expired token");
            }

            // (Optional) check if user is still active
            var user = await _userManager.FindByIdAsync(storedToken.UserId);
            if (user == null)
            {
                return new NotFoundResponse("User not found");
            }

            // generate new tokens
            var roles = (await _userManager.GetRolesAsync(user)).ToArray();
            var newAccessToken = CreateAccessToken(user, roles, validAudience);

            return new OkResponse<(string AccessToken, string RefreshToken)>((newAccessToken, request.RefreshToken));
        }

        public async Task<RefreshToken?> ValidateRefreshTokenAsync(string token)
        {
            var hash = ComputeHash(token);
            var rec = await _db.AsQueryable<RefreshToken>(r => r.TokenHash == hash && r.ClientId == _config.ClientId, false)
                .FirstOrDefaultAsync();

            if (rec == null || rec.RevokedAt != null)
            {
                return null;
            }
            if (rec.ExpiresAt < DateTimeOffset.UtcNow)
            {
                rec.RevokedAt = DateTimeOffset.UtcNow;
                rec.IsDeprecated = true;
                await _db.UpdateAsync(rec);
            }
            return rec;
        }

        #region Private Section
        private string ComputeHash(string token)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(bytes);
        }

        private SigningCredentials GetSigningCredentials()
        {
            var key = Encoding.UTF8.GetBytes(_config.PrivateKey);
            var secret = new SymmetricSecurityKey(key);
            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        }

        private List<Claim> GetClaims(AppUser user, string[] roles)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Iss, _config.Issuer),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("client_id", _config.ClientId) // optional
            };
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            return claims;
        }

        private JwtSecurityToken GetJwtSecurityToken(List<Claim> claims, SigningCredentials creds, DateTime now, string audience)
        {
            var jwt = new JwtSecurityToken(
                    issuer: _config.Issuer,
                    audience: audience,
                    claims: claims,
                    notBefore: now,
                    expires: now.AddHours(_config.Span),
                    signingCredentials: creds
                ); ;

            //if (_config.Audience.Count == 1)
            //{
            //    // one audience → use built-in
            //    jwt = new JwtSecurityToken(
            //        issuer: _config.Issuer,
            //        audience: _audience,
            //        claims: claims,
            //        notBefore: now,
            //        expires: now.AddHours(_config.Span),
            //        signingCredentials: creds
            //    );
            //}
            //else
            //{
            //    // multiple audiences → aud must be array
            //    jwt = new JwtSecurityToken(
            //        issuer: _config.Issuer,
            //        claims: claims,
            //        notBefore: now,
            //        expires: now.AddHours(_config.Span),
            //        signingCredentials: creds
            //    );

            //    // manually override aud
            //    jwt.Payload["aud"] = _config.Audience;
            //}

            return jwt;
        }
        #endregion
    }
}
