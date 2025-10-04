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
using Microsoft.EntityFrameworkCore;

namespace KwikNestaIdentity.Svc.Application.Commands.Verification
{
    public class ResendOtpCommandHandler : IRequestHandler<ResendOtpCommand, GenericResponseDto>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEFCoreCrudKit _crudKit;
        private readonly IRabbitMQPubSub _pubSub;

        public ResendOtpCommandHandler(UserManager<AppUser> userManager,
                                       IEFCoreCrudKit crudKit,
                                       IRabbitMQPubSub pubSub)
        {
            _userManager = userManager;
            _crudKit = crudKit;
            _pubSub = pubSub;
        }

        public async Task<GenericResponseDto> Handle(ResendOtpCommand request, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByEmailAsync(request.Email) ??
                throw new NotFoundException("No user found with this email");

            if (user.EmailConfirmed && request.Type == OtpType.AccountVerification)
            {
                throw new ForbiddenException("Account already verified. Please login");
            }

            var existingOtp = await _crudKit
               .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == request.Type, false)
               .OrderByDescending(o => o.ExpiresAt)
               .FirstOrDefaultAsync(cancellationToken);

            var otp = CommonHelpers.GenerateOtp();
            var (Hash, Salt) = CommonHelpers.HashOtp(otp);
            var otpEntry = user.Map(Hash, Salt, request.Type);
            await _crudKit.InsertAsync(otpEntry, cancellation: cancellationToken);

            // Send activation email to user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                otp, request.Type.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            if (existingOtp != null)
            {
                await _crudKit.DeleteAsync(existingOtp, cancellation: cancellationToken);
            }

            return new GenericResponseDto(200, $"OTP successfully resent. Please check your email");
        }
    }
}
