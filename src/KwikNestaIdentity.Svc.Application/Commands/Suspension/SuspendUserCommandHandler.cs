using API.Common.Response.Model.Exceptions;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.Guid;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNesta.Contracts.Commands;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace KwikNestaIdentity.Svc.Application.Commands.Suspension
{
    public class SuspendUserCommandHandler : IRequestHandler<SuspendUserCommand, ApiResult<string>>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEFCoreCrudKit _crudKit;
        private readonly IRabbitMQPubSub _pubSub;
        private readonly ClaimsPrincipal? _claimsPrincipal;

        public SuspendUserCommandHandler(UserManager<AppUser> userManager,
                                         IEFCoreCrudKit crudKit,
                                         IRabbitMQPubSub pubSub,
                                         IHttpContextAccessor accessor)
        {
            _userManager = userManager;
            _crudKit = crudKit;
            _pubSub = pubSub;
            _claimsPrincipal = accessor.HttpContext?.User;
        }

        public async Task<ApiResult<string>> Handle(SuspendUserCommand request, CancellationToken cancellationToken)
        {
            var loggedInUserId = CommonHelpers.GetUserId(_claimsPrincipal);
            var loggedInUser = await _userManager.FindByIdAsync(loggedInUserId) ??
                throw new NotFoundException("Access denied!!! You're not authorized to perform this action.");

            var roles = (await _userManager.GetRolesAsync(loggedInUser))?.ToList();
            if (roles == null || !roles.Contains(SystemRoles.SuperAdmin.GetDescription()) && !roles.Contains(SystemRoles.Admin.GetDescription()))
            {
                throw new ForbiddenException("Access denied!!! You're not authorized to perform this action.");
            }

            var userToUpdate = await _userManager.FindByIdAsync(request.UserId) ??
                throw new NotFoundException("User information not found.");

            if (userToUpdate.Status == UserStatus.Suspended)
            {
                throw new BadRequestException("User already suspended");
            }

            userToUpdate.Status = UserStatus.Suspended;
            userToUpdate.UpdatedAt = DateTime.UtcNow;
            userToUpdate.StatusChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(userToUpdate);

            //Revoke refresh tokens
            var tokens = await _crudKit.AsQueryable<RefreshToken>(rt => rt.UserId.Equals(userToUpdate.Id), true)
                .ToListAsync(cancellationToken);
            if (tokens.Count != 0)
            {
                await _crudKit.DeleteRangeAsync(tokens, cancellation: cancellationToken);
            }

            // Notify the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(userToUpdate.Email!, userToUpdate.FirstName,
                EmailType.AccountSuspension, request.Reason.GetDescription()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Log action
            var audit = new AuditCommand
            {
                PerformedBy = loggedInUserId,
                DomainId = userToUpdate.Id.ToGuid(),
                Domain = AuditDomain.Identity,
                Action = AuditAction.SuspendedAccount,
                TargetId = userToUpdate.Id
            };
            await _pubSub.PublishAsync(new AuditCommand
            {
                PerformedBy = loggedInUserId,
                DomainId = userToUpdate.Id.ToGuid(),
                Domain = AuditDomain.Identity,
                Action = AuditAction.SuspendedAccount,
                TargetId = userToUpdate.Id
            }, routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new ApiResult<string>("Account successfully suspended.");
        }
    }
}
