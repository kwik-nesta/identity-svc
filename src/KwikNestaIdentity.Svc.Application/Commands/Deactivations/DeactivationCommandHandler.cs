using API.Common.Response.Model.Exceptions;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.Guid;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Contract.Responses;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace KwikNestaIdentity.Svc.Application.Commands.Deactivations
{
    public class DeactivationCommandHandler : IRequestHandler<DeactivationCommand, ApiResult<string>>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEFCoreCrudKit _crudKit;
        private readonly IRabbitMQPubSub _pubSub;
        private readonly ClaimsPrincipal? _claim;

        public DeactivationCommandHandler(UserManager<AppUser> userManager,
                                         IEFCoreCrudKit crudKit,
                                         IRabbitMQPubSub pubSub,
                                         IHttpContextAccessor accessor)
        {
            _userManager = userManager;
            _crudKit = crudKit;
            _pubSub = pubSub;
            _claim = accessor.HttpContext?.User;
        }

        public async Task<ApiResult<string>> Handle(DeactivationCommand request, CancellationToken cancellationToken)
        {
            var loggedInUserId = CommonHelpers.GetUserId(_claim);

            if (string.IsNullOrWhiteSpace(loggedInUserId) || !loggedInUserId.Equals(request.UserId))
            {
                throw new ForbiddenException("Access denied!!! You're not authorized to perform this action.");
            }

            var user = await _userManager.FindByIdAsync(request.UserId) ??
                throw new NotFoundException("User not found!");

            user.Status = UserStatus.Deactivated;
            user.UpdatedAt = DateTime.UtcNow;
            user.StatusChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            //Revoke refresh tokens
            var tokens = await _crudKit.AsQueryable<RefreshToken>(rt => rt.UserId.Equals(user.Id), true)
                .ToListAsync(cancellationToken);
            if (tokens.Count != 0)
            {
                await _crudKit.DeleteRangeAsync(tokens, cancellation: cancellationToken);
            }

            // Notify the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!,
                user.FirstName, EmailType.AccountDeactivation),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(loggedInUserId, user.Id, user.Id.ToGuid(),
                AuditDomain.Identity, AuditAction.DeactivatedAccount),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new ApiResult<string>(ResponseMessages.AccountDeactivated);
        }
    }
}
