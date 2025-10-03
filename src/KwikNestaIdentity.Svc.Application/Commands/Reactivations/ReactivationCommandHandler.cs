using API.Common.Response.Model.Exceptions;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Date;
using CSharpTypes.Extensions.Enumeration;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Contract.Responses;
using KwikNestaIdentity.Svc.Domain.Entities;
using KwikNestaIdentity.Svc.Domain.Enums;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace KwikNestaIdentity.Svc.Application.Commands.Reactivations
{
    public class ReactivationCommandHandler : IRequestHandler<ReactivationCommand, GenericResponseDto>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEFCoreCrudKit _crudKit;
        private readonly IRabbitMQPubSub _pubSub;

        public ReactivationCommandHandler(UserManager<AppUser> userManager,
                                         IEFCoreCrudKit crudKit,
                                         IRabbitMQPubSub pubSub)
        {
            _userManager = userManager;
            _crudKit = crudKit;
            _pubSub = pubSub;
        }

        public async Task<GenericResponseDto> Handle(ReactivationCommand request, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(request.Otp) || string.IsNullOrWhiteSpace(request.Email))
            {
                throw new BadRequestException(ResponseMessages.InvalidRequest);
            }

            var user = await _userManager.FindByEmailAsync(request.Email) ??
                throw new NotFoundException(ResponseMessages.UserNotFoundWithEmail);

            var otpEntry = await _crudKit
                .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == OtpType.AccountReactivation, true)
                .OrderByDescending(o => o.ExpiresAt).FirstOrDefaultAsync(cancellationToken) ??
                    throw new NotFoundException(ResponseMessages.InvalidOTP); ;

            bool isValid = CommonHelpers.VerifyOtp(request.Otp, otpEntry.OtpHash, otpEntry.OtpSalt)
                          && otpEntry.ExpiresAt.IsLaterThan(DateTime.UtcNow);
            if (!isValid)
            {
                throw new ForbiddenException(ResponseMessages.OTPExpired);
            }

            user.UpdatedAt = DateTime.UtcNow;
            user.Status = UserStatus.Active;
            user.StatusChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Notify the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!,
                user.FirstName, EmailType.AccountReactivationNotification),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new GenericResponseDto(200, ResponseMessages.AccountReactivated);
        }
    }
}
