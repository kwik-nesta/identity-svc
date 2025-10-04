using API.Common.Response.Model.Exceptions;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.String;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Extensions;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Application.Validations;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace KwikNestaIdentity.Svc.Application.Commands.Register
{
    public class RegisterCommandHandler : IRequestHandler<RegisterCommand, ApiResult<RegisterResponseDto>>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IHttpContextAccessor _accessor;
        private readonly IRabbitMQPubSub _pubSub;
        private readonly IEFCoreCrudKit _crudKit;

        public RegisterCommandHandler(UserManager<AppUser> userManager,
                                      IHttpContextAccessor accessor,
                                      IRabbitMQPubSub pubSub,
                                      IEFCoreCrudKit crudKit)
        {
            _userManager = userManager;
            _accessor = accessor;
            _pubSub = pubSub;
            _crudKit = crudKit;
        }

        public async Task<ApiResult<RegisterResponseDto>> Handle(RegisterCommand request, CancellationToken cancellationToken)
        {
            // For loggedin admin/super admin to register another admin
            var userContext = _accessor.HttpContext?.User;
            var hasPermission = (await GetUserRoles(userContext))
                .Contains(SystemRoles.SuperAdmin);

            if (!hasPermission && (request.Role == SystemRoles.SuperAdmin || request.Role == SystemRoles.Admin))
            {
                throw new ForbiddenException("You have no permission to add an Admin user");
            }

            var validate = new RegistrationValidator().Validate(request);
            if (!validate.IsValid)
            {
                throw new BadRequestException(validate.Errors.FirstOrDefault()?.ErrorMessage ?? "Registration failed");
            }

            //check for existing user
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                throw new ForbiddenException($"A user already exists with this email: {request.Email}");
            }

            //Insert record
            var user = request.Map();
            var createResult = await _userManager.CreateAsync(user, request.Password);
            if (!createResult.Succeeded)
            {
                throw new BadRequestException(createResult.Errors?.FirstOrDefault()?.Description ?? "User registration failed. Please try again");
            }

            var roleResult = await _userManager.AddToRoleAsync(user, request.Role.GetDescription());
            if (!roleResult.Succeeded)
            {
                await _userManager.DeleteAsync(user);
                throw new BadRequestException($"Registration failed. {roleResult.Errors.FirstOrDefault()?.Description}");
            }

            // Generate OTP
            var otp = CommonHelpers.GenerateOtp();
            var (hash, salt) = CommonHelpers.HashOtp(otp);
            var otpEntry = user.Map(hash, salt);
            await _crudKit.InsertAsync(otpEntry, cancellation: cancellationToken);

            // Send activation email to user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                otp, OtpType.AccountVerification.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Return to the user
            return new ApiResult<RegisterResponseDto>(new RegisterResponseDto(user.Email, "Registration successful. Please check your mail for your activation code"));
        }

        #region Private methods
        private async Task<List<SystemRoles>> GetUserRoles(ClaimsPrincipal? userClaim)
        {
            var roles = new List<SystemRoles>();
            var userId = CommonHelpers.GetUserId(userClaim);
            if (userId.IsNotNullOrEmpty())
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return roles;
                }

                return (await _userManager.GetRolesAsync(user)).ToList().ParseValues<SystemRoles>();
            }

            return roles;
        }
        #endregion
    }
}
