using API.Common.Response.Model.Exceptions;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Enumeration;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Extensions;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace KwikNestaIdentity.Svc.Application.Commands.PasswordRequests
{
    public class PasswordResetCommandHandler : IRequestHandler<PasswordResetCommand, GenericResponseDto>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEFCoreCrudKit _crudKit;
        private readonly IRabbitMQPubSub _pubSub;

        public PasswordResetCommandHandler(UserManager<AppUser> userManager,
                                                  IEFCoreCrudKit crudKit,
                                                  IRabbitMQPubSub pubSub)
        {
            _userManager = userManager;
            _crudKit = crudKit;
            _pubSub = pubSub;
        }

        public async Task<GenericResponseDto> Handle(PasswordResetCommand request, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByEmailAsync(request.Email) ??
               throw new NotFoundException($"No user found with this email: {request.Email}");

            var otp = CommonHelpers.GenerateOtp();
            var (Hash, Salt) = CommonHelpers.HashOtp(otp);
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var otpEntry = user.Map(Hash, Salt, OtpType.ResetPassword, token);

            await _crudKit.InsertAsync(otpEntry, cancellation: cancellationToken);

            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                otp, OtpType.ResetPassword.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new GenericResponseDto(200, "Password reset request successful. Please enter the OTP sent to your email to complete the process");
        }
    }
}