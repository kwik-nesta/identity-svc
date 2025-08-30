using API.Common.Response.Model.Responses;
using KwikNestaIdentity.Svc.Contract.Requests;
using KwikNestaIdentity.Svc.Domain.Enums;

namespace KwikNestaIdentity.Svc.Application.Services.Interfaces
{
    public interface IUserService
    {
        string GetLoggedInUserId();
        Task<ApiBaseResponse> GetLoggedInUserLeanAsync();
        Task<List<SystemRoles>> GetUserRoles();
        Task<ApiBaseResponse> UpdateBasicDetails(UpdateUserBasicDetailsRequest request);
        Task<ApiBaseResponse> UpdateUserLastLogin(string id);
    }
}