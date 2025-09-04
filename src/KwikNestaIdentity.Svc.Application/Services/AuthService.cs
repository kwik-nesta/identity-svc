using API.Common.Response.Model.Responses;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Date;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.Guid;
using CSharpTypes.Extensions.List;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Extensions;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Application.Services.Interfaces;
using KwikNestaIdentity.Svc.Application.Validations;
using KwikNestaIdentity.Svc.Contract.DTOs;
using KwikNestaIdentity.Svc.Contract.Requests;
using KwikNestaIdentity.Svc.Contract.Responses;
using KwikNestaIdentity.Svc.Domain.Entities;
using KwikNestaIdentity.Svc.Domain.Enums;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace KwikNestaIdentity.Svc.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IHttpContextAccessor _accessor;
        private readonly IEFCoreCrudKit _crudKit;
        private readonly IRabbitMQPubSub _pubSub;

        public AuthService(UserManager<AppUser> userManager,
                           SignInManager<AppUser> signInManager,
                           IHttpContextAccessor accessor,
                           IEFCoreCrudKit crudKit,
                           IRabbitMQPubSub pubSub)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _accessor = accessor;
            _crudKit = crudKit;
            _pubSub = pubSub;
        }

        public async Task<ApiBaseResponse> ValidateUser(LoginRequest request)
        {
            //var validation = new LoginValidator().Validate(request);
            //if (!validation.IsValid)
            //{
            //    return new BadRequestResponse(validation.Errors.FirstOrDefault()?.ErrorMessage ?? "Invalid input");
            //}

            var user = await _userManager.FindByNameAsync(request.UserName);
            if (user == null)
            {
                return new NotFoundResponse("User not found");
            }

            if (!user.EmailConfirmed || user.Status != UserStatus.Active)
            {
                return CommonHelpers.GetStatusResponse(user.Status);
            }

            var check = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            if (!check.Succeeded)
            {
                return new ForbiddenResponse("Wrong password");
            }

            var roles = (await _userManager.GetRolesAsync(user)).ToArray();
            if (roles == null || roles.Length == 0)
            {
                return new UnauthorizedResponse("User have no assigned role.");
            }

            return new OkResponse<(AppUser User, string[] Roles)>((user, roles));
        }

        public async Task<ApiBaseResponse> RegisterAsync(RegistrationRequest request, bool forAdmin = false)
        {
            var hasPermission = (await CommonHelpers.GetUserRoles(_userManager, _accessor.HttpContext?.User))
                .Contains(SystemRoles.SuperAdmin);

            if (!hasPermission && (request.Role == SystemRoles.SuperAdmin || request.Role == SystemRoles.Admin))
            {
                return new ForbiddenResponse("You have no permission to add an Admin user");
            }

            //var validate = new RegistrationValidator().Validate(request);
            //if (!validate.IsValid)
            //{
            //    return new BadRequestResponse(validate.Errors.FirstOrDefault()?.ErrorMessage ?? "Registration failed");
            //}

            //var existingUser = await _userManager.FindByEmailAsync(request.Email);
            //if (existingUser != null)
            //{
            //    return new ForbiddenResponse($"A user already exists with this email: {request.Email}");
            //}

            //var user = request.Map();
            //var createResult = await _userManager.CreateAsync(user, request.Password);
            //if (!createResult.Succeeded)
            //{
            //    return new BadRequestResponse(createResult.Errors?.FirstOrDefault()?.Description ?? "User registration failed. Please try again");
            //}

            //var roleResult = await _userManager.AddToRoleAsync(user, request.Role.GetDescription());
            //if (!roleResult.Succeeded)
            //{
            //    await _userManager.DeleteAsync(user);
            //    return new BadRequestResponse($"Registration failed. {roleResult.Errors.FirstOrDefault()?.Description}");
            //}

            //// OTP
            //var otp = CommonHelpers.GenerateOtp();
            //var (hash, salt) = CommonHelpers.HashOtp(otp);
            //var otpEntry = user.Map(hash, salt);
            //await _crudKit.InsertAsync(otpEntry);

            //// Send activation email to user
            //await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
            //    otp, OtpType.AccountVerification.ToEmailType()),
            //    routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Return to the user
            return new OkResponse<RegistrationDto>(new RegistrationDto
            {
                //Email = user.Email,
                Message = "Registration successful. Please check your mail for your activation code"
            });
        }

        public async Task<ApiBaseResponse> ResendOtpAsync(OtpResendRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new NotFoundResponse("No user found with this email");
            }

            if (user.EmailConfirmed && request.Type == OtpType.AccountVerification)
            {
                return new ForbiddenResponse("Account already verified. Please login");
            }

            var existingOtp = await _crudKit
               .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == request.Type, false)
               .OrderByDescending(o => o.ExpiresAt)
               .FirstOrDefaultAsync();

            var otp = CommonHelpers.GenerateOtp();
            var (Hash, Salt) = CommonHelpers.HashOtp(otp);
            var otpEntry = user.Map(Hash, Salt, request.Type);
            await _crudKit.InsertAsync(otpEntry);

            // Send activation email to user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                otp, request.Type.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            if (existingOtp != null)
            {
                await _crudKit.DeleteAsync(existingOtp);
            }

            return new OkResponse<SuccessStringDto>(new SuccessStringDto($"OTP successfully resent. Please check your email"));
        }

        public async Task<ApiBaseResponse> RequestPasswordResetAsync(EmailPayload request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new NotFoundResponse("No user found with this email");
            }

            var otp = CommonHelpers.GenerateOtp();
            var (Hash, Salt) = CommonHelpers.HashOtp(otp);
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var otpEntry = user.Map(Hash, Salt, OtpType.ResetPassword, token);

            await _crudKit.InsertAsync(otpEntry);

            // Send activation email to user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                otp, OtpType.ResetPassword.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new OkResponse<SuccessStringDto>(new SuccessStringDto($"Password reset request successful. Please enter the OTP sent to your email to complete the process"));
        }

        public async Task<ApiBaseResponse> VerifyAccountAsync(OtpVerificationRequest request)
        {
            if (!request.IsValid)
            {
                return new BadRequestResponse(ResponseMessages.InvalidRequest);
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new NotFoundResponse(ResponseMessages.UserNotFoundWithEmail);
            }

            var otpEntry = await _crudKit
                .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == OtpType.AccountVerification, true)
                .OrderByDescending(o => o.ExpiresAt)
                .FirstOrDefaultAsync();

            if (otpEntry == null)
            {
                return new NotFoundResponse(ResponseMessages.InvalidOTP);
            }

            bool isValid = CommonHelpers.VerifyOtp(request.Otp, otpEntry.OtpHash, otpEntry.OtpSalt)
                          && otpEntry.ExpiresAt.IsLaterThan(DateTime.UtcNow);

            if (!isValid)
            {
                return new ForbiddenResponse(ResponseMessages.OTPExpired);
            }

            user.EmailConfirmed = true;
            user.UpdatedAt = DateTime.UtcNow;
            user.Status = UserStatus.Active;
            await _userManager.UpdateAsync(user);

            await _crudKit.DeleteAsync(otpEntry);
            return new OkResponse<SuccessStringDto>(new SuccessStringDto("Account successfully verified. Please proceed to login"));
        }

        public async Task<ApiBaseResponse> PasswordResetAsync(PasswordResetRequest request)
        {
            if (!request.IsValid)
            {
                return new BadRequestResponse($"Invalid request");
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new NotFoundResponse($"No user found with the specified email address");
            }

            var otpEntry = await _crudKit
                .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == OtpType.ResetPassword, true)
                .OrderByDescending(o => o.ExpiresAt)
                .FirstOrDefaultAsync();

            if (otpEntry == null)
            {
                return new NotFoundResponse($"No valid OTP found for this user");
            }

            bool isValid = CommonHelpers.VerifyOtp(request.Otp, otpEntry.OtpHash, otpEntry.OtpSalt)
                          && otpEntry.ExpiresAt.IsLaterThan(DateTime.UtcNow) && otpEntry.Token!.IsNotNullOrEmpty();

            if (!isValid)
            {
                return new ForbiddenResponse("OTP has expired. Please request for a new one.");
            }

            var result = await _userManager.ResetPasswordAsync(user, Uri.UnescapeDataString(otpEntry.Token!), request.NewPassword);
            if (!result.Succeeded)
            {
                return new BadRequestResponse($"{result.Errors.FirstOrDefault()?.Description}" ?? "Password reset failed.");
            }

            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            await _crudKit.DeleteAsync(otpEntry);

            // Notify the user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                EmailType.PasswordResetNotification),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new OkResponse<SuccessStringDto>(new SuccessStringDto("Password successfully reset. Please login with your new password"));
        }

        public async Task<ApiBaseResponse> ChangePasswordAsync(PasswordChangeRequest request)
        {
            if (!request.IsValid)
            {
                return new BadRequestResponse("Invalid request");
            }

            var loggedInUserId = CommonHelpers.GetUserId(_accessor.HttpContext?.User);
            var user = await _userManager.FindByIdAsync(loggedInUserId);
            if (user == null)
            {
                return new ForbiddenResponse("Access denied");
            }

            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
            if (!result.Succeeded)
            {
                return new BadRequestResponse($"{result.Errors.FirstOrDefault()?.Description}");
            }

            // Notify the user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                EmailType.PasswordResetNotification),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(loggedInUserId, user.Id, user.Id.ToGuid(),
                AuditDomain.User, AuditAction.ChangedPassword),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new OkResponse<SuccessStringDto>(new SuccessStringDto("Password changed successfully. Please login with the new password"));
        }

        public async Task<ApiBaseResponse> SuspendUserAccountAsync(UserSuspensionRequest request)
        {
            var loggedInUserId = CommonHelpers.GetUserId(_accessor.HttpContext?.User);
            var loggedInUser = await _userManager.FindByIdAsync(loggedInUserId);
            if (loggedInUser == null)
            {
                return new ForbiddenResponse("Access denied!!! You're not authorized to perform this action.");
            }

            var roles = (await _userManager.GetRolesAsync(loggedInUser))?.ToList();
            if (roles == null || !roles.Contains(SystemRoles.SuperAdmin.GetDescription()) && !roles.Contains(SystemRoles.Admin.GetDescription()))
            {
                return new ForbiddenResponse("Access denied!!! You're not authorized to perform this action.");
            }

            var userToUpdate = await _userManager.FindByIdAsync(request.UserId);
            if (userToUpdate == null)
            {
                return new NotFoundResponse("User not found!");
            }

            userToUpdate.Status = UserStatus.Suspended;
            userToUpdate.UpdatedAt = DateTime.UtcNow;
            userToUpdate.StatusChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(userToUpdate);

            //Revoke refresh tokens
            var tokens = await _crudKit.AsQueryable<RefreshToken>(rt => rt.UserId.Equals(userToUpdate.Id), true)
                .ToListAsync();
            if (tokens.Count != 0)
            {
                await _crudKit.DeleteRangeAsync(tokens);
            }

            // Notify the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(userToUpdate.Email!, userToUpdate.FirstName,
                EmailType.AccountSuspension, request.Reason.GetDescription()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(loggedInUserId, userToUpdate.Id, userToUpdate.Id.ToGuid(),
                AuditDomain.User, AuditAction.SuspendedAccount),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new OkResponse<SuccessStringDto>(new SuccessStringDto($"Account successfully suspended."));
        }

        public async Task<ApiBaseResponse> LiftAccountSuspensionAsync(string userId)
        {
            var loggedInUserId = CommonHelpers.GetUserId(_accessor.HttpContext?.User);
            var loggedInUser = await _userManager.FindByIdAsync(loggedInUserId);
            if (loggedInUser == null)
            {
                return new ForbiddenResponse("Access denied!!! You're not authorized to perform this action.");
            }

            var roles = (await _userManager.GetRolesAsync(loggedInUser))?.ToList();
            if (roles == null || !roles.Contains(SystemRoles.SuperAdmin.GetDescription()) && !roles.Contains(SystemRoles.Admin.GetDescription()))
            {
                return new ForbiddenResponse("Access denied!!! You're not authorized to perform this action.");
            }

            var userToUpdate = await _userManager.FindByIdAsync(userId);
            if (userToUpdate == null)
            {
                return new NotFoundResponse("User not found!");
            }

            userToUpdate.Status = UserStatus.Active;
            userToUpdate.UpdatedAt = DateTime.UtcNow;
            userToUpdate.StatusChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(userToUpdate);

            // Notify the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(userToUpdate.Email!,
                userToUpdate.FirstName, EmailType.AdminAccountReactivation),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(loggedInUserId, userToUpdate.Id, userToUpdate.Id.ToGuid(),
                AuditDomain.User, AuditAction.ReactivatedAccount),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new OkResponse<SuccessStringDto>(new SuccessStringDto($"Account successfully reactivated."));
        }

        public async Task<ApiBaseResponse> DeactivateAccountAsync(string userId)
        {
            var loggedInUserId = CommonHelpers.GetUserId(_accessor.HttpContext?.User);
            if (string.IsNullOrWhiteSpace(loggedInUserId) || !loggedInUserId.Equals(userId))
            {
                return new ForbiddenResponse("Access denied!!! You're not authorized to perform this action.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new NotFoundResponse("User not found!");
            }

            user.Status = UserStatus.Deactivated;
            user.UpdatedAt = DateTime.UtcNow;
            user.StatusChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            //Revoke refresh tokens
            var tokens = await _crudKit.AsQueryable<RefreshToken>(rt => rt.UserId.Equals(user.Id), true)
                .ToListAsync();
            if (tokens.Count != 0)
            {
                await _crudKit.DeleteRangeAsync(tokens);
            }

            // Notify the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!,
                user.FirstName, EmailType.AccountDeactivation),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(loggedInUserId, user.Id, user.Id.ToGuid(),
                AuditDomain.User, AuditAction.DeactivatedAccount),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new OkResponse<SuccessStringDto>(new SuccessStringDto(ResponseMessages.AccountDeactivated));
        }

        public async Task<ApiBaseResponse> RequestAccountReactivationAsync(EmailPayload request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new NotFoundResponse(ResponseMessages.UserNotFoundWithEmail);
            }

            var otp = CommonHelpers.GenerateOtp();
            var (Hash, Salt) = CommonHelpers.HashOtp(otp);
            var otpEntry = user.Map(Hash, Salt, OtpType.AccountReactivation);

            await _crudKit.InsertAsync(otpEntry);

            // Email the OTP to the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!,
                user.FirstName, OtpType.AccountReactivation.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new OkResponse<SuccessStringDto>(new SuccessStringDto(ResponseMessages.AccountReactivationRequested));
        }

        public async Task<ApiBaseResponse> ReactivateAccountAsync(OtpVerificationRequest request)
        {
            if (!request.IsValid)
            {
                return new BadRequestResponse(ResponseMessages.InvalidRequest);
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new NotFoundResponse(ResponseMessages.UserNotFoundWithEmail);
            }

            var otpEntry = await _crudKit
                .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == OtpType.AccountReactivation, true)
                .OrderByDescending(o => o.ExpiresAt)
                .FirstOrDefaultAsync();

            if (otpEntry == null)
            {
                return new NotFoundResponse(ResponseMessages.InvalidOTP);
            }

            bool isValid = CommonHelpers.VerifyOtp(request.Otp, otpEntry.OtpHash, otpEntry.OtpSalt)
                          && otpEntry.ExpiresAt.IsLaterThan(DateTime.UtcNow);

            if (!isValid)
            {
                return new ForbiddenResponse(ResponseMessages.OTPExpired);
            }

            user.UpdatedAt = DateTime.UtcNow;
            user.Status = UserStatus.Active;
            user.StatusChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Notify the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!,
                user.FirstName, EmailType.AccountReactivationNotification),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new OkResponse<SuccessStringDto>(new SuccessStringDto(ResponseMessages.AccountReactivated));
        }
    }
}