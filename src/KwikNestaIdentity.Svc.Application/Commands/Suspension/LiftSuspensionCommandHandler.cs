using API.Common.Response.Model.Exceptions;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.Guid;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace KwikNestaIdentity.Svc.Application.Commands.Suspension
{
    public class LiftSuspensionCommandHandler : IRequestHandler<LiftSuspensionCommand, ApiResult<string>>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IRabbitMQPubSub _pubSub;
        private readonly ClaimsPrincipal? _claim;

        public LiftSuspensionCommandHandler(UserManager<AppUser> userManager,
                                         IRabbitMQPubSub pubSub,
                                         IHttpContextAccessor accessor)
        {
            _userManager = userManager;
            _pubSub = pubSub;
            _claim = accessor.HttpContext?.User;
        }

        public async Task<ApiResult<string>> Handle(LiftSuspensionCommand request, CancellationToken cancellationToken)
        {
            var loggedInUserId = CommonHelpers.GetUserId(_claim);
            var loggedInUser = await _userManager.FindByIdAsync(loggedInUserId) ??
                throw new ForbiddenException("Access denied!!! You're not authorized to perform this action.");

            var roles = (await _userManager.GetRolesAsync(loggedInUser))?.ToList();
            if (roles == null || !roles.Contains(SystemRoles.SuperAdmin.GetDescription()) && !roles.Contains(SystemRoles.Admin.GetDescription()))
            {
                throw new ForbiddenException("Access denied!!! You're not authorized to perform this action.");
            }

            var userToUpdate = await _userManager.FindByIdAsync(request.UserId) ??
                throw new NotFoundException("User not found");

            userToUpdate.Status = UserStatus.Active;
            userToUpdate.UpdatedAt = DateTime.UtcNow;
            userToUpdate.StatusChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(userToUpdate);

            // Notify the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(userToUpdate.Email!,
                userToUpdate.FirstName, EmailType.AdminAccountReactivation),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(loggedInUserId, userToUpdate.Id, userToUpdate.Id.ToGuid(),
                AuditDomain.Identity, AuditAction.ReactivatedAccount),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new ApiResult<string>("Account successfully reactivated.");
        }
    }
}
