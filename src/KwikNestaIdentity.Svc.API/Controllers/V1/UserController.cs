using API.Common.Response.Model.ControllerHelpers;
using API.Common.Response.Model.Extensions;
using KwikNestaIdentity.Svc.Application.Services.Interfaces;
using KwikNestaIdentity.Svc.Contract.DTOs;
using KwikNestaIdentity.Svc.Contract.Requests;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KwikNestaIdentity.Svc.API.Controllers.V1
{
    [Route("api/v{version:apiversion}/users")]
    [ApiVersion("1.0")]
    [ApiController]
    public class UserController : ApiControllerBase
    {
        private readonly IServiceManager _service;

        public UserController(IServiceManager service)
        {
            _service = service;
        }

        /// <summary>
        /// Gets logged in user details
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetLoggedInUserDetails()
        {
            var result = await _service.User.GetLoggedInUserLeanAsync();
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<UserLeanDto>());
        }

        /// <summary>
        /// Updates user's basic details
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPut("update-basic")]
        [Authorize]
        public async Task<IActionResult> UpdateBasicDetails(UpdateUserBasicDetailsRequest request)
        {
            var result = await _service.User.UpdateBasicDetails(request);
            if (!result.Success)
            {
                return ProcessError(result);
            }

            return Ok(result.GetResult<SuccessStringDto>());
        }
    }
}
