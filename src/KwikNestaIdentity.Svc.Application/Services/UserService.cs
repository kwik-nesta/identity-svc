using API.Common.Response.Model.Responses;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.Guid;
using CSharpTypes.Extensions.Object;
using CSharpTypes.Extensions.String;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Application.Services.Interfaces;
using KwikNestaIdentity.Svc.Application.Validations;
using KwikNestaIdentity.Svc.Contract.DTOs;
using KwikNestaIdentity.Svc.Contract.Requests;
using KwikNestaIdentity.Svc.Contract.Responses;
using KwikNestaIdentity.Svc.Domain.Entities;
using KwikNestaIdentity.Svc.Domain.Enums;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace KwikNestaIdentity.Svc.Application.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IHttpContextAccessor _accessor;
        private readonly IRabbitMQPubSub _pubSub;

        public UserService(UserManager<AppUser> userManager,
                           IHttpContextAccessor accessor,
                           IRabbitMQPubSub pubSub)
        {
            _userManager = userManager;
            _accessor = accessor;
            _pubSub = pubSub;
        }  

        public async Task<ApiBaseResponse> UpdateBasicDetails(UpdateUserBasicDetailsRequest request)
        {
            var validate = new UserBasicDetailsRequestValidator().Validate(request);
            if (!validate.IsValid)
            {
                return new BadRequestResponse(validate.Errors.FirstOrDefault()?.ErrorMessage ?? "User details update failed");
            }

            var userId = GetLoggedInUserId();
            var existingUser = await _userManager.FindByIdAsync(userId);
            if (existingUser == null)
            {
                return new NotFoundResponse($"No user found");
            }

            existingUser = existingUser.Map(request);
            await _userManager.UpdateAsync(existingUser);

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(existingUser.Id, existingUser.Id, existingUser.Id.ToGuid(),
                AuditDomain.User, AuditAction.UpdatedProfile),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new OkResponse<SuccessStringDto>(new SuccessStringDto("User details successfully updated."));
        }

        
        public async Task<ApiBaseResponse> GetLoggedInUserLeanAsync()
        {
            var userId = GetLoggedInUserId();
            if (userId.IsNullOrEmpty())
            {
                return new UnauthorizedResponse("User is unauthorized");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new NotFoundResponse($"No user information found");
            }

            return new OkResponse<UserLeanDto>(user.Map());
        }

        public async Task<ApiBaseResponse> UpdateUserLastLogin(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return new NotFoundResponse(ResponseMessages.UserNotFoundWithId);
            }

            user.LastLogin = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(id, user.Id, user.Id.ToGuid(),
                AuditDomain.User, AuditAction.LoogedIn),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new OkResponse<bool>(true);
        }

        public string GetLoggedInUserId()
        {
            return CommonHelpers.GetUserId(_accessor.HttpContext?.User);
        }

        public async Task<List<SystemRoles>> GetUserRoles()
        {
            return await CommonHelpers.GetUserRoles(_userManager, _accessor.HttpContext?.User);
        }
    }
}