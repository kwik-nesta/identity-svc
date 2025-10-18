using KwikNestaIdentity.Svc.Domain.Entities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace KwikNestaIdentity.Svc.Application.Helpers
{
    public class AuthHelpers
    {
        public static string CreateAccessToken(AppUser user, string[] roles, Jwt settings)
        {
            var claims = GetClaims(user, roles, settings.Issuer);
            var creds = GetSigningCredentials(settings.PrivateKey);
            var jwt = GetJwtSecurityToken(claims, creds, settings, DateTime.UtcNow, settings.Audience);

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        public static (string Token, RefreshToken RefreshToken) CreateRefreshToken(string userId, Jwt settings)
        {
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            var hash = ComputeHash(token);
            var record = new RefreshToken
            {
                Id = Guid.NewGuid(),
                TokenHash = hash,
                UserId = userId,
                ClientId = settings.ClientId,
                ExpiresAt = DateTimeOffset.UtcNow.Add(TimeSpan.FromDays(settings.Span))
            };

            return (token, record);
        }

        public static string ComputeHash(string token)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(bytes);
        }

        public static SigningCredentials GetSigningCredentials(string privateKey)
        {
            var key = Encoding.UTF8.GetBytes(privateKey);
            var secret = new SymmetricSecurityKey(key);
            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        }

        public static List<Claim> GetClaims(AppUser user, string[] roles, string issuer)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Iss, issuer),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
            };

            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            return claims;
        }

        public static JwtSecurityToken GetJwtSecurityToken(List<Claim> claims,
                                                           SigningCredentials creds,
                                                           Jwt jwtSettings,
                                                           DateTime now,
                                                           string audience)
        {
            var jwt = new JwtSecurityToken(
                    issuer: jwtSettings.Issuer,
                    audience: audience,
                    claims: claims,
                    notBefore: now,
                    expires: now.AddHours(jwtSettings.Span),
                    signingCredentials: creds
                );
            return jwt;
        }
    }
}
