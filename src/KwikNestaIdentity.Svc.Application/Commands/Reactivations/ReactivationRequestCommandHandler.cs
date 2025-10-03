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
using KwikNestaIdentity.Svc.Contract.Responses;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace KwikNestaIdentity.Svc.Application.Commands.Reactivations
{
    public class ReactivationRequestCommandHandler : IRequestHandler<ReactivationRequestCommand, GenericResponseDto>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEFCoreCrudKit _crudKit;
        private readonly IRabbitMQPubSub _pubSub;

        public ReactivationRequestCommandHandler(UserManager<AppUser> userManager,
                                         IEFCoreCrudKit crudKit,
                                         IRabbitMQPubSub pubSub)
        {
            _userManager = userManager;
            _crudKit = crudKit;
            _pubSub = pubSub;
        }

        public async Task<GenericResponseDto> Handle(ReactivationRequestCommand request, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByEmailAsync(request.Email) ??
                throw new NotFoundException(ResponseMessages.UserNotFoundWithEmail);

            var otp = CommonHelpers.GenerateOtp();
            var (Hash, Salt) = CommonHelpers.HashOtp(otp);
            var otpEntry = user.Map(Hash, Salt, OtpType.AccountReactivation);

            await _crudKit.InsertAsync(otpEntry, cancellation: cancellationToken);

            // Email the OTP to the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!,
                user.FirstName, otp, OtpType.AccountReactivation.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new GenericResponseDto(200, ResponseMessages.AccountReactivationRequested);
        }
    }
}
