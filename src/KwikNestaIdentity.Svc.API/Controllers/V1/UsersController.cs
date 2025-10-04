using KwikNestaIdentity.Svc.Application.Commands.UpdateBasicDetails;
using KwikNestaIdentity.Svc.Application.Queries.LoggedInUser;
using KwikNestaIdentity.Svc.Application.Queries.Users;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KwikNestaIdentity.Svc.API.Controllers.V1
{
    [Route("api/v{version:apiversion}/user")]
    [ApiVersion("1.0")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IMediator _mediator;

        public UsersController(IMediator mediator)
        {
            _mediator = mediator;
        }

        /// <summary>
        /// Gets the current logged in user details
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [Authorize]
        [HttpGet("current")]
        public async Task<IActionResult> Current()
        {
            var response = await _mediator.Send(new CurrentUserQuery());
            return Ok(response);
        }

        /// <summary>
        /// Updates user basic details
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [Authorize]
        [HttpPatch("update")]
        public async Task<IActionResult> UpdateDetails([FromBody] UpdateBasicUserDetailsCommand command)
        {
            var response = await _mediator.Send(command);
            return Ok(response);
        }

        /// <summary>
        /// Get user by id
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpGet("{id}")]
        public async Task<IActionResult> GetById([FromRoute] string id)
        {
            var response = await _mediator.Send(new GetUserQuery(id));
            return Ok(response);
        }

        /// <summary>
        /// Get users by their ids
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> GetByIds([FromBody] List<string> ids)
        {
            var response = await _mediator.Send(new GetUsersQuery(ids));
            return Ok(response);
        }

        /// <summary>
        /// Get paged user details
        /// </summary>
        /// <param name="command"></param>
        /// <returns></returns>
        [HttpGet]
        [Authorize(Roles = "Admin, SuperAdmin")]
        public async Task<IActionResult> GetPaged([FromQuery] GetPagedUsersQuery query)
        {
            var response = await _mediator.Send(query);
            return Ok(response);
        }
    }
}