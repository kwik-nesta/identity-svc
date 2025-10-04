using API.Common.Response.Model.Exceptions;
using CSharpTypes.Extensions.Date;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNesta.Contracts.Enums;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Contract.Responses;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace KwikNestaIdentity.Svc.Application.Commands.Verification
{
    public class VerificationCommandHandler : IRequestHandler<VerificationCommand, GenericResponseDto>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IEFCoreCrudKit _crudKit;

        public VerificationCommandHandler(UserManager<AppUser> userManager,
                                          IEFCoreCrudKit crudKit)
        {
            _userManager = userManager;
            _crudKit = crudKit;
        }

        public async Task<GenericResponseDto> Handle(VerificationCommand request, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(request.Otp) || string.IsNullOrWhiteSpace(request.Email))
            {
                throw new BadRequestException(ResponseMessages.InvalidRequest);
            }

            var user = await _userManager.FindByEmailAsync(request.Email) ??
                throw new NotFoundException(ResponseMessages.UserNotFoundWithEmail);

            var otpEntry = await _crudKit
                .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == OtpType.AccountVerification, true)
                .OrderByDescending(o => o.ExpiresAt)
                .FirstOrDefaultAsync(cancellationToken) ?? throw new NotFoundException(ResponseMessages.InvalidOTP);

            bool isValid = CommonHelpers.VerifyOtp(request.Otp, otpEntry.OtpHash, otpEntry.OtpSalt)
                          && otpEntry.ExpiresAt.IsLaterThan(DateTime.UtcNow);

            if (!isValid)
            {
                throw new ForbiddenException(ResponseMessages.OTPExpired);
            }

            user.EmailConfirmed = true;
            user.UpdatedAt = DateTime.UtcNow;
            user.Status = UserStatus.Active;
            await _userManager.UpdateAsync(user);
            await _crudKit.DeleteAsync(otpEntry, cancellation: cancellationToken);

            return new GenericResponseDto(200, "Account successfully verified. Please proceed to login");
        }
    }
}