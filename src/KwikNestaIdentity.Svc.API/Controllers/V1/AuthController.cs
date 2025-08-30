using API.Common.Response.Model.ControllerHelpers;
using API.Common.Response.Model.Extensions;
using KwikNestaIdentity.Svc.API.Filters;
using KwikNestaIdentity.Svc.Application.Services.Interfaces;
using KwikNestaIdentity.Svc.Contract.DTOs;
using KwikNestaIdentity.Svc.Contract.Requests;
using KwikNestaIdentity.Svc.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace KwikNestaIdentity.Svc.API.Controllers.V1
{
    [Route("api/v{version:apiversion}/auth")]
    [ApiVersion("1.0")]
    [ApiController]
    public class AuthController : ApiControllerBase
    {
        private readonly IServiceManager _service;
        private readonly IOptions<Jwt> _jwtOptions;

        public AuthController(IServiceManager service, IOptions<Jwt> jwtOptions)
        {
            _service = service;
            _jwtOptions = jwtOptions;
        }

        /// <summary>
        /// Logs in a user
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            var validationResult = await _service.Auth.ValidateUser(request);
            if (!validationResult.Success)
            {
                return ProcessError(validationResult);
            }

            var result = validationResult.GetResult<(AppUser User, string[] Roles)>();
            var accessToken = _service.Token.CreateAccessToken(result.User, result.Roles, _jwtOptions.Value.Audience);
            var refreshToken = await _service.Token.CreateAndSaveRefreshTokenAsync(result.User.Id);
            await _service.User.UpdateUserLastLogin(result.User.Id);
            return Ok(new LoginTokenDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
            });
        }

        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPut("refresh")]
        [Authorize]
        [RequireAudienceHeader]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request, [FromHeader(Name = "Audience")] string audience)
        {
            var baseResult = await _service.Token.RefreshTokenAsync(request, audience);
            if (!baseResult.Success)
            {
                return ProcessError(baseResult);
            }

            var result = baseResult.GetResult<(string AccessToken, string RefreshToken)>();
            return Ok(new LoginTokenDto
            {
                AccessToken = result.AccessToken,
                RefreshToken = result.RefreshToken,
            });
        }

        /// <summary>
        /// Registers a new user
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegistrationRequest request)
        {
            var result = await _service.Auth.RegisterAsync(request);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<RegistrationDto>());
        }

        /// <summary>
        /// Verifies newly created accounts
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPut("verify")]
        public async Task<IActionResult> Verify(OtpVerificationRequest request)
        {
            var result = await _service.Auth.VerifyAccountAsync(request);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }

        /// <summary>
        /// Resends OTP
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPost("resend-otp")]
        public async Task<IActionResult> ResendOtp(OtpResendRequest request)
        {
            var result = await _service.Auth.ResendOtpAsync(request);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }

        /// <summary>
        /// Requests password reset
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPost("request-password-reset")]
        public async Task<IActionResult> RequestPasswordReset(EmailPayload request)
        {
            var result = await _service.Auth.RequestPasswordResetAsync(request);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }

        /// <summary>
        /// Password reset
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPut("reset-password")]
        public async Task<IActionResult> PasswordReset(PasswordResetRequest request)
        {
            var result = await _service.Auth.PasswordResetAsync(request);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }

        /// <summary>
        /// Password change
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPut("change-password")]
        [Authorize]
        public async Task<IActionResult> PasswordChange(PasswordChangeRequest request)
        {
            var result = await _service.Auth.ChangePasswordAsync(request);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }

        /// <summary>
        /// Suspend a user
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPut("suspend")]
        [Authorize(Roles = "SuperAdmin, Admin")]
        public async Task<IActionResult> Suspend(UserSuspensionRequest request)
        {
            var result = await _service.Auth.SuspendUserAccountAsync(request);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }

        /// <summary>
        /// Reactivate suspended user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPut("lift-suspension/{userId}")]
        [Authorize(Roles = "SuperAdmin, Admin")]
        public async Task<IActionResult> LiftSuspension([FromRoute] string userId)
        {
            var result = await _service.Auth.LiftAccountSuspensionAsync(userId);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }

        /// <summary>
        /// Deactivates the current user
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPut("deactivate/{userId}")]
        [Authorize]
        public async Task<IActionResult> Deactivate([FromRoute] string userId)
        {
            var result = await _service.Auth.DeactivateAccountAsync(userId);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }

        /// <summary>
        /// Requests account reactivation
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPut("request-reactivation")]
        public async Task<IActionResult> ReactivationRequest(EmailPayload request)
        {
            var result = await _service.Auth.RequestAccountReactivationAsync(request);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }

        /// <summary>
        /// Reactivate an account
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPut("reactivate")]
        public async Task<IActionResult> Reactivate(OtpVerificationRequest request)
        {
            var result = await _service.Auth.ReactivateAccountAsync(request);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }
    }
}