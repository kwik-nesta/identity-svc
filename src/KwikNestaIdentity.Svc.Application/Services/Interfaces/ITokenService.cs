using API.Common.Response.Model.Responses;
using KwikNestaIdentity.Svc.Contract.Requests;
using KwikNestaIdentity.Svc.Domain.Entities;

namespace KwikNestaIdentity.Svc.Application.Services.Interfaces
{
    public interface ITokenService
    {
        string CreateAccessToken(AppUser user, string[] roles, string validAudience);
        Task<string> CreateAndSaveRefreshTokenAsync(string userId);
        Task<ApiBaseResponse> RefreshTokenAsync(RefreshTokenRequest request, string validAudience);
        Task<RefreshToken?> ValidateRefreshTokenAsync(string token);
    }
}
