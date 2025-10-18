using KwikNestaIdentity.Svc.Application.Commands.Deactivations;
using KwikNestaIdentity.Svc.Application.Commands.Login;
using KwikNestaIdentity.Svc.Application.Commands.PasswordRequests;
using KwikNestaIdentity.Svc.Application.Commands.Reactivations;
using KwikNestaIdentity.Svc.Application.Commands.RefreshTokens;
using KwikNestaIdentity.Svc.Application.Commands.Register;
using KwikNestaIdentity.Svc.Application.Commands.Suspension;
using KwikNestaIdentity.Svc.Application.Commands.Verification;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KwikNestaIdentity.Svc.API.Controllers.V1
{
    [Route("api/v{version:apiversion}/auth")]
    [ApiVersion("1.0")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IMediator _mediator;

        public AuthController(IMediator mediator)
        {
            _mediator = mediator;
        }

        /// <summary>
        /// Signs in users
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpPost("sign-in")]
        public async Task<IActionResult> Login([FromBody] LoginCommand command)
        {
            return Ok(await _mediator.Send(command));
        }

        /// <summary>
        /// Signs up users
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpPost("sign-up")]
        public async Task<IActionResult> Register([FromBody] RegisterCommand command)
        {
            return Ok(await _mediator.Send(command));
        }

        /// <summary>
        /// Verify account
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpPut("confirm")]
        public async Task<IActionResult> Verify([FromBody] VerificationCommand command)
        {
            var result = await _mediator.Send(command);
            return Ok(result);
        }

        /// <summary>
        /// Refreshes token
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenCommand command)
        {
            var result = await _mediator.Send(command);
            return Ok(result);
        }

        /// <summary>
        /// Requests new OTP
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpPost("request-otp")]
        public async Task<IActionResult> RequestOtp([FromBody] ResendOtpCommand command)
        {
            var result = await _mediator.Send(command);
            return Ok(result);
        }

        /// <summary>
        /// Resets password
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpPatch("reset-password")]
        public async Task<IActionResult> PasswordReset([FromBody] PasswordResetCommand command)
        {
            var result = await _mediator.Send(command);
            return Ok(result);
        }

        /// <summary>
        /// Change forgotten password
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpPatch("change-forgot-password")]
        public async Task<IActionResult> ChangeForgot([FromBody] ChangeForgotPasswordCommand command)
        {
            var result = await _mediator.Send(command);
            return Ok(result);
        }

        /// <summary>
        /// Changes password
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPatch("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordCommand command)
        {
            var result = await _mediator.Send(command);
            return Ok(result);
        }

        /// <summary>
        /// Deactivates accounts
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPut("deactivate-account")]
        public async Task<IActionResult> Deactivate([FromRoute] string userId)
        {
            var result = await _mediator.Send(new DeactivationCommand
            {
                UserId = userId
            });
            return Ok(result);
        }

        /// <summary>
        /// Reactivates deactivated accounts
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpPatch("reactivate-account")]
        public async Task<IActionResult> Reactivate([FromBody] ReactivationCommand command)
        {
            var result = await _mediator.Send(command);
            return Ok(result);
        }

        /// <summary>
        /// Reactivation requests
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpPatch("request-reactivation")]
        public async Task<IActionResult> RequestReactivation([FromBody] ReactivationRequestCommand command)
        {
            var result = await _mediator.Send(command);
            return Ok(result);
        }

        /// <summary>
        /// Lifts suspensions
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin, SuperAdmin")]
        [HttpPatch("lift-account-suspension/{userId}")]
        public async Task<IActionResult> LiftSuspension([FromRoute] string userId)
        {
            var result = await _mediator.Send(new LiftSuspensionCommand
            {
                UserId = userId
            });
            return Ok(result);
        }

        /// <summary>
        /// Suspends accounts
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [Authorize(Roles = "Admin, SuperAdmin")]
        [HttpPut("suspend-account")]
        public async Task<IActionResult> Suspend([FromBody] SuspendUserCommand command)
        {
            var result = await _mediator.Send(command);
            return Ok(result);
        }
    }
}