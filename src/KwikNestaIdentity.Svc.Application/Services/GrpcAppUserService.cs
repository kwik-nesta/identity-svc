using API.Common.Response.Model.Responses;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.Guid;
using Grpc.Core;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Application.Validations;
using KwikNestaIdentity.Svc.Contract;
using KwikNestaIdentity.Svc.Contract.DTOs;
using KwikNestaIdentity.Svc.Contract.Protos;
using KwikNestaIdentity.Svc.Domain.Entities;
using KwikNestaIdentity.Svc.Domain.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace KwikNestaIdentity.Svc.Application.Services
{
    public class GrpcAppUserService : AppUserService.AppUserServiceBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IRabbitMQPubSub _pubSub;

        public GrpcAppUserService(UserManager<AppUser> userManager,
                           IRabbitMQPubSub pubSub)
        {
            _userManager = userManager;
            _pubSub = pubSub;
        }

        /// <summary>
        /// Get loggedin user details
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<GetLoggedInUserResponse> GetLoggedInUser(Empty request, ServerCallContext context)
        {
            var userId = CommonHelpers.GetUserId(context.GetHttpContext()?.User);
            var user = await _userManager.FindByIdAsync(userId) ??
                throw new RpcException(new Status(StatusCode.NotFound, "User information not found."));

            return new GetLoggedInUserResponse
            {
                User = Map(user)
            };
        }

        /// <summary>
        /// Update user basic details
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<UpdateBasicUserDetailsResponse> UpdateBasicUserDetails(UpdateBasicUserDetailsRequest request, ServerCallContext context)
        {
            var validate = new UserBasicDetailsRequestValidator().Validate(request);
            if (!validate.IsValid)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, validate.Errors.FirstOrDefault()?.ErrorMessage ?? "Invalid request"));
            }

            var userId = CommonHelpers.GetUserId(context.GetHttpContext()?.User);
            var existingUser = await _userManager.FindByIdAsync(userId) ??
                throw new RpcException(new Status(StatusCode.NotFound, "No user found"));

            existingUser = existingUser.Map(request);
            await _userManager.UpdateAsync(existingUser);

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(existingUser.Id, existingUser.Id, existingUser.Id.ToGuid(),
                AuditDomain.User, AuditAction.UpdatedProfile),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new UpdateBasicUserDetailsResponse
            {
                Response =
                {
                    Message = "User details successfully updated.",
                    Status = 200
                }
            };
        }

        /// <summary>
        /// Get user by id
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<GetUserByIdResponse> GetUserById(GetUserByIdRequest request, ServerCallContext context)
        {
            var user = await _userManager.FindByIdAsync(request.UserId) ??
                throw new RpcException(new Status(StatusCode.NotFound, "User information not found."));

            return new GetUserByIdResponse
            {
                User = Map(user)
            };
        }

        /// <summary>
        /// Get users by their ids
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<GetUsersByIdsResponse> GetUsersByIds(GetUsersByIdsRequest request, ServerCallContext context)
        {
            var users = await _userManager.Users
                .Where(u => request.UserIds.Contains(u.Id))
                .ToListAsync(context.CancellationToken);

            return new GetUsersByIdsResponse
            {
                Users = { users.Select(Map)  }
            };
        }

        private static User Map(AppUser user)
        {
            return new User
            {
                Id = user.Id,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                MiddleName = user.OtherName,
                PhoneNumber = user.PhoneNumber,
                Gender = user.Gender.GetDescription(),
                Status = EnumMapper.Map<UserStatus, GrpcUserStatus>(user.Status),
                StatusDescription = user.Status.GetDescription()
            };
        }
    }
}