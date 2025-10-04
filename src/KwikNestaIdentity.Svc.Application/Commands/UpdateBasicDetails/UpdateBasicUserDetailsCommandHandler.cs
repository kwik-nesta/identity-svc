using API.Common.Response.Model.Exceptions;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.Guid;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Application.Validations;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace KwikNestaIdentity.Svc.Application.Commands.UpdateBasicDetails
{
    public class UpdateBasicUserDetailsCommandHandler : IRequestHandler<UpdateBasicUserDetailsCommand, ApiResult<string>>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IRabbitMQPubSub _pubSub;
        private readonly ClaimsPrincipal? _user;

        public UpdateBasicUserDetailsCommandHandler(UserManager<AppUser> userManager,
                                                    IHttpContextAccessor accessor,
                                                    IRabbitMQPubSub pubSub)
        {
            _userManager = userManager;
            _pubSub = pubSub;
            _user = accessor.HttpContext?.User;
        }

        public async Task<ApiResult<string>> Handle(UpdateBasicUserDetailsCommand request, CancellationToken cancellationToken)
        {
            var validate = new UserBasicDetailsRequestValidator().Validate(request);
            if (!validate.IsValid)
            {
                throw new BadRequestException(validate.Errors.FirstOrDefault()?.ErrorMessage ?? "Invalid request");
            }

            var userId = CommonHelpers.GetUserId(_user);
            var existingUser = await _userManager.FindByIdAsync(userId) ??
                throw new NotFoundException("No user found");

            existingUser = existingUser.Map(request);
            await _userManager.UpdateAsync(existingUser);

            await _pubSub.PublishAsync(AuditLog.Initialize(existingUser.Id, existingUser.Id, existingUser.Id.ToGuid(),
                AuditDomain.Identity, AuditAction.UpdatedProfile),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new ApiResult<string>("User details successfully updated.");
        }
    }
}
