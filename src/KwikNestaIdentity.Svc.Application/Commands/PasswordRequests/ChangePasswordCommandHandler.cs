using API.Common.Response.Model.Exceptions;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.Guid;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Application.Validations;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace KwikNestaIdentity.Svc.Application.Commands.PasswordRequests
{
    public class ChangePasswordCommandHandler : IRequestHandler<ChangePasswordCommand, GenericResponseDto>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IRabbitMQPubSub _pubSub;
        private readonly ClaimsPrincipal? _claimsPrincipal;

        public ChangePasswordCommandHandler(UserManager<AppUser> userManager,
                                            IRabbitMQPubSub pubSub,
                                            IHttpContextAccessor accessor)
        {
            _userManager = userManager;
            _pubSub = pubSub;
            _claimsPrincipal = accessor.HttpContext?.User;
        }

        public async Task<GenericResponseDto> Handle(ChangePasswordCommand request, CancellationToken cancellationToken)
        {
            var loggedInUserId = CommonHelpers.GetUserId(_claimsPrincipal);
            var user = await _userManager.FindByIdAsync(loggedInUserId) ??
                throw new ForbiddenException("Access denied");

            var validator = new ChangePasswordValidator().Validate(request);
            if (!validator.IsValid)
            {
                throw new BadRequestException(validator.Errors.FirstOrDefault()?.ErrorMessage ?? "Invalid inputs.");
            }

            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
            if (!result.Succeeded)
            {
                throw new BadRequestException($"{result.Errors.FirstOrDefault()?.Description}");
            }

            // Notify the user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                EmailType.PasswordResetNotification),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(loggedInUserId, user.Id, user.Id.ToGuid(),
                AuditDomain.Identity, AuditAction.ChangedPassword),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new GenericResponseDto(200, "Password changed successfully. Please login with the new password");
        }
    }
}