using API.Common.Response.Model.Exceptions;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Date;
using CSharpTypes.Extensions.Enumeration;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace KwikNestaIdentity.Svc.Application.Commands.PasswordRequests
{
    public class ChangeForgotPasswordCommandHandler : IRequestHandler<ChangeForgotPasswordCommand, ApiResult<string>>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IRabbitMQPubSub _pubSub;
        private readonly IEFCoreCrudKit _crudKit;

        public ChangeForgotPasswordCommandHandler(UserManager<AppUser> userManager,
                                                  IRabbitMQPubSub pubSub,
                                                  IEFCoreCrudKit crudKit)
        {
            _userManager = userManager;
            _pubSub = pubSub;
            _crudKit = crudKit;
        }

        public async Task<ApiResult<string>> Handle(ChangeForgotPasswordCommand request, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Otp))
            {
                throw new BadRequestException("Invalid request. Email and OTP are required.");
            }

            if (!request.PasswordMatch)
            {
                throw new BadRequestException("New Password and Confirm New Password must match.");
            }

            var user = await _userManager.FindByEmailAsync(request.Email) ??
                            throw new NotFoundException($"No user found with the specified email address");

            var otpEntry = await _crudKit
                .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == OtpType.ResetPassword, true)
                .OrderByDescending(o => o.ExpiresAt).FirstOrDefaultAsync() ??
                    throw new NotFoundException("No valid OTP found for this user");

            bool isValid = CommonHelpers.VerifyOtp(request.Otp, otpEntry.OtpHash, otpEntry.OtpSalt)
                          && otpEntry.ExpiresAt.IsLaterThan(DateTime.UtcNow) && !string.IsNullOrWhiteSpace(otpEntry.Token);

            if (!isValid)
            {
                throw new BadRequestException("OTP has expired. Please request for a new one.");
            }

            var result = await _userManager.ResetPasswordAsync(user, Uri.UnescapeDataString(otpEntry.Token!), request.NewPassword);
            if (!result.Succeeded)
            {
                throw new BadRequestException($"{result.Errors.FirstOrDefault()?.Description}" ?? "Password reset failed.");
            }

            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            await _crudKit.DeleteAsync(otpEntry);

            // Notify the user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                EmailType.PasswordResetNotification),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new ApiResult<string>("Password successfully reset. Please login with your new password");
        }
    }
}
