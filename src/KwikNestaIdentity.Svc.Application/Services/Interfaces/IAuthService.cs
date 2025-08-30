using API.Common.Response.Model.Responses;
using KwikNestaIdentity.Svc.Contract.Requests;

namespace KwikNestaIdentity.Svc.Application.Services.Interfaces
{
    public interface IAuthService
    {
        Task<ApiBaseResponse> ChangePasswordAsync(PasswordChangeRequest request);
        Task<ApiBaseResponse> DeactivateAccountAsync(string userId);
        Task<ApiBaseResponse> LiftAccountSuspensionAsync(string userId);
        Task<ApiBaseResponse> PasswordResetAsync(PasswordResetRequest request);
        Task<ApiBaseResponse> ReactivateAccountAsync(OtpVerificationRequest request);
        Task<ApiBaseResponse> RegisterAsync(RegistrationRequest request, bool forAdmin = false);
        Task<ApiBaseResponse> RequestAccountReactivationAsync(EmailPayload request);
        Task<ApiBaseResponse> RequestPasswordResetAsync(EmailPayload request);
        Task<ApiBaseResponse> ResendOtpAsync(OtpResendRequest request);
        Task<ApiBaseResponse> SuspendUserAccountAsync(UserSuspensionRequest request);
        Task<ApiBaseResponse> ValidateUser(LoginRequest request);
        Task<ApiBaseResponse> VerifyAccountAsync(OtpVerificationRequest request);
    }
}