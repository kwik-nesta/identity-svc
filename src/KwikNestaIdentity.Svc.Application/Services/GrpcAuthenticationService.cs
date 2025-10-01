using API.Common.Response.Model.Extensions;
using API.Common.Response.Model.Responses;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Date;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.Guid;
using EFCore.CrudKit.Library.Data.Interfaces;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Extensions;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Application.Validations;
using KwikNestaIdentity.Svc.Contract.Protos;
using KwikNestaIdentity.Svc.Contract.Responses;
using KwikNestaIdentity.Svc.Domain.Entities;
using KwikNestaIdentity.Svc.Domain.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Empty = Google.Protobuf.WellKnownTypes.Empty;

namespace KwikNestaIdentity.Svc.Application.Services
{
    public class GrpcAuthenticationService : AuthenticationService.AuthenticationServiceBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IEFCoreCrudKit _crudKit;
        private readonly IRabbitMQPubSub _pubSub;
        private readonly Jwt _config;

        public GrpcAuthenticationService(UserManager<AppUser> userManager,
                           SignInManager<AppUser> signInManager,
                           IEFCoreCrudKit crudKit,
                           IRabbitMQPubSub pubSub,
                           IOptions<Jwt> config)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _crudKit = crudKit;
            _pubSub = pubSub;
            _config = config.Value;
        }

        /// <summary>
        ///Ping
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<StringValue> Ping(Empty request, ServerCallContext context)
        {
            return await Task.FromResult(new StringValue { Value = "OK" });
        }

        /// <summary>
        /// Login
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<LoginResponse> Login(LoginRequest request, ServerCallContext context)
        {
            var validationResult = await ValidateUser(request);
            if (!validationResult.Success)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, validationResult.Message));
            }

            var (User, Roles) = validationResult.GetResult<(AppUser User, string[] Roles)>();
            var accessToken = CreateAccessToken(User, Roles, _config.Audience);
            var refreshToken = await CreateAndSaveRefreshTokenAsync(User.Id);

            User.UpdatedAt = DateTime.UtcNow;
            User.LastLogin = DateTime.UtcNow;
            await _userManager.UpdateAsync(User);

            await _pubSub.PublishAsync(AuditLog.Initialize(User.Id, User.Id, User.Id.ToGuid(),
                AuditDomain.User, AuditAction.LoogedIn),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new LoginResponse
            {
                Tokens = new TokenResponse
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                }
            };
        }

        /// <summary>
        /// Register
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<RegisterResponse> Register(RegisterRequest request, ServerCallContext context)
        {
            // For loggedin admin/super admin to register another admin
            var userContext = context.GetHttpContext()?.User;
            var hasPermission = (await CommonHelpers.GetUserRoles(_userManager, userContext))
                .Contains(SystemRoles.SuperAdmin);

            if (!hasPermission && (request.SystemRole == GrpcSystemRole.SuperAdmin || request.SystemRole == GrpcSystemRole.Admin))
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, "You have no permission to add an Admin user"));
            }

            //validate inputs
            var validate = new RegistrationValidator().Validate(request);
            if (!validate.IsValid)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, validate.Errors.FirstOrDefault()?.ErrorMessage ?? "Registration failed"));
            }

            //check for existing user
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, $"A user already exists with this email: {request.Email}"));
            }

            //Insert record
            var user = request.Map();
            var createResult = await _userManager.CreateAsync(user, request.Password);
            if (!createResult.Succeeded)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, createResult.Errors?.FirstOrDefault()?.Description ?? "User registration failed. Please try again"));
            }

            //add user to role
            var role = EnumMapper.Map<GrpcSystemRole, SystemRoles>(request.SystemRole);
            var roleResult = await _userManager.AddToRoleAsync(user, role.GetDescription());
            if (!roleResult.Succeeded)
            {
                await _userManager.DeleteAsync(user);
                throw new RpcException(new Status(StatusCode.InvalidArgument, $"Registration failed. {roleResult.Errors.FirstOrDefault()?.Description}"));
            }

            // Generate OTP
            var otp = CommonHelpers.GenerateOtp();
            var (hash, salt) = CommonHelpers.HashOtp(otp);
            var otpEntry = user.Map(hash, salt);
            await _crudKit.InsertAsync(otpEntry);

            // Send activation email to user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                otp, OtpType.AccountVerification.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Return to the user
            return new RegisterResponse
            {
                Email = user.Email,
                Message = "Registration successful. Please check your mail for your activation code"
            };
        }

        /// <summary>
        /// Generate Refresh Token
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<RefreshTokenResponse> Refresh(RefreshTokenRequest request, ServerCallContext context)
        {

            if (request == null || string.IsNullOrWhiteSpace(request.RefreshToken))
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Invalid refresh token"));
            }

            var storedToken = await ValidateRefreshTokenAsync(request.RefreshToken) ??
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Invalid or expired token"));

            // (Optional) check if user is still active
            var user = await _userManager.FindByIdAsync(storedToken.UserId) ??
                throw new RpcException(new Status(StatusCode.NotFound, "User not found"));

            if(user.Status != UserStatus.Active)
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, "User is inactive. Please reactivate your account to continue."));
            }
            
            // generate new tokens
            var roles = (await _userManager.GetRolesAsync(user)).ToArray();
            var newAccessToken = CreateAccessToken(user, roles, _config.Audience);
            return new RefreshTokenResponse
            {
                Token = new TokenResponse 
                {
                    AccessToken = newAccessToken,
                    RefreshToken = request.RefreshToken
                }
            };
        }

        /// <summary>
        /// Verify Account
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<VerifyAccountResponse> VerifyAccount(VerifyAccountRequest request, ServerCallContext context)
        {
            if (string.IsNullOrWhiteSpace(request.Request.Otp) || string.IsNullOrWhiteSpace(request.Request.Email))
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, ResponseMessages.InvalidRequest));
            }

            var user = await _userManager.FindByEmailAsync(request.Request.Email) ?? 
                throw new RpcException(new Status(StatusCode.NotFound, ResponseMessages.UserNotFoundWithEmail));

            var otpEntry = await _crudKit
                .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == OtpType.AccountVerification, true)
                .OrderByDescending(o => o.ExpiresAt)
                .FirstOrDefaultAsync();

            if (otpEntry == null)
            {
                throw new RpcException(new Status(StatusCode.NotFound, ResponseMessages.InvalidOTP));
            }

            bool isValid = CommonHelpers.VerifyOtp(request.Request.Otp, otpEntry.OtpHash, otpEntry.OtpSalt)
                          && otpEntry.ExpiresAt.IsLaterThan(DateTime.UtcNow);

            if (!isValid)
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, ResponseMessages.OTPExpired));
            }

            user.EmailConfirmed = true;
            user.UpdatedAt = DateTime.UtcNow;
            user.Status = UserStatus.Active;
            await _userManager.UpdateAsync(user);

            await _crudKit.DeleteAsync(otpEntry);
            return new VerifyAccountResponse
            {
                Response = new StringResponse
                {
                    Message = "Account successfully verified. Please proceed to login",
                    Status = 200
                }
            };
        }

        /// <summary>
        /// Resend OTP
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<ResendOtpResponse> ResendOtp(ResendOtpRequest request, ServerCallContext context)
        {
            var user = await _userManager.FindByEmailAsync(request.Email) ??
                throw new RpcException(new Status(StatusCode.NotFound, "No user found with this email"));
            
            if (user.EmailConfirmed && request.Type == GrpcOtpType.AccountVerification)
            {
                throw new RpcException(new Status(StatusCode.AlreadyExists, "Account already verified. Please login"));
            }

            var otpType = EnumMapper.Map<GrpcOtpType, OtpType>(request.Type);
            var existingOtp = await _crudKit
               .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == otpType, false)
               .OrderByDescending(o => o.ExpiresAt)
               .FirstOrDefaultAsync();

            var otp = CommonHelpers.GenerateOtp();
            var (Hash, Salt) = CommonHelpers.HashOtp(otp);
            var otpEntry = user.Map(Hash, Salt, otpType);
            await _crudKit.InsertAsync(otpEntry);

            // Send activation email to user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                otp, otpType.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            if (existingOtp != null)
            {
                await _crudKit.DeleteAsync(existingOtp);
            }

            return new ResendOtpResponse
            {
                Response = new StringResponse
                {
                    Message = $"OTP successfully resent. Please check your email",
                    Status = 200
                }
            };
        }

        /// <summary>
        /// Request password reset
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<PasswordResetResponse> PasswordReset(PasswordResetRequest request, ServerCallContext context)
        {
            var user = await _userManager.FindByEmailAsync(request.Request.Email) ?? 
                throw new RpcException(new Status(StatusCode.NotFound, $"No user found with this email: {request.Request.Email}"));

            var otp = CommonHelpers.GenerateOtp();
            var (Hash, Salt) = CommonHelpers.HashOtp(otp);
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var otpEntry = user.Map(Hash, Salt, OtpType.ResetPassword, token);

            await _crudKit.InsertAsync(otpEntry);

            // Send activation email to user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                otp, OtpType.ResetPassword.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new PasswordResetResponse
            {
                Response = new StringResponse
                {
                    Message = $"Password reset request successful. Please enter the OTP sent to your email to complete the process",
                    Status = 200
                }
            };
        }

        /// <summary>
        /// Change password after request
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<ChangeForgotPasswordResponse> ChangeForgotPassword(ChangeForgotPasswordRequest request, ServerCallContext context)
        {
            if (string.IsNullOrWhiteSpace(request.Request.Email) || string.IsNullOrWhiteSpace(request.Request.Otp))
            {
                throw new RpcException(new Status(StatusCode.Unimplemented, "Invalid request"));
            }

            var user = await _userManager.FindByEmailAsync(request.Request.Email) ??
                            throw new RpcException(new Status(StatusCode.NotFound, $"No user found with the specified email address"));

            var otpEntry = await _crudKit
                .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == OtpType.ResetPassword, true)
                .OrderByDescending(o => o.ExpiresAt).FirstOrDefaultAsync() ?? 
                    throw new RpcException(new Status(StatusCode.NotFound, "No valid OTP found for this user"));

            bool isValid = CommonHelpers.VerifyOtp(request.Request.Otp, otpEntry.OtpHash, otpEntry.OtpSalt)
                          && otpEntry.ExpiresAt.IsLaterThan(DateTime.UtcNow) && !string.IsNullOrWhiteSpace(otpEntry.Token);

            if (!isValid)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, "OTP has expired. Please request for a new one."));
            }

            var result = await _userManager.ResetPasswordAsync(user, Uri.UnescapeDataString(otpEntry.Token!), request.NewPassword);
            if (!result.Succeeded)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, $"{result.Errors.FirstOrDefault()?.Description}" ?? "Password reset failed."));
            }

            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            await _crudKit.DeleteAsync(otpEntry);

            // Notify the user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                EmailType.PasswordResetNotification),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new ChangeForgotPasswordResponse
            {
                Response = new StringResponse
                {
                    Message = "Password successfully reset. Please login with your new password",
                    Status = 200
                }
            };
        }

        /// <summary>
        /// Change known password
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<ChangePasswordResponse> ChangePassword(ChangePasswordRequest request, ServerCallContext context)
        {
            var loggedInUserId = CommonHelpers.GetUserId(context.GetHttpContext()?.User);
            var user = await _userManager.FindByIdAsync(loggedInUserId) ?? 
                throw new RpcException(new Status(StatusCode.NotFound, "Access denied"));
            
            var validator = new ChangePasswordValidator().Validate(request);
            if (!validator.IsValid)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, validator.Errors.FirstOrDefault()?.ErrorMessage ?? "Invalid inputs."));
            }

            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
            if (!result.Succeeded)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, $"{result.Errors.FirstOrDefault()?.Description}"));
            }

            // Notify the user
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!, user.FirstName,
                EmailType.PasswordResetNotification),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(loggedInUserId, user.Id, user.Id.ToGuid(),
                AuditDomain.User, AuditAction.ChangedPassword),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new ChangePasswordResponse
            {
                Response = new StringResponse
                {
                    Message = "Password changed successfully. Please login with the new password",
                    Status = 200
                }
            };
        }

        /// <summary>
        /// Suspend user
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<SuspendUserResponse> SuspendUser(SuspendUserRequest request, ServerCallContext context)
        {
            var loggedInUserId = CommonHelpers.GetUserId(context.GetHttpContext()?.User);
            var loggedInUser = await _userManager.FindByIdAsync(loggedInUserId) ?? 
                throw new RpcException(new Status(StatusCode.NotFound, "Access denied!!! You're not authorized to perform this action."));

            var roles = (await _userManager.GetRolesAsync(loggedInUser))?.ToList();
            if (roles == null || !roles.Contains(SystemRoles.SuperAdmin.GetDescription()) && !roles.Contains(SystemRoles.Admin.GetDescription()))
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Access denied!!! You're not authorized to perform this action."));
            }

            var userToUpdate = await _userManager.FindByIdAsync(request.UserId) ??
                throw new RpcException(new Status(StatusCode.NotFound, "User information not found."));

            if(userToUpdate.Status == UserStatus.Suspended)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, "User already suspended"));
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
            var reason = EnumMapper.Map<GrpcSuspensionReason, SuspensionReasons>(request.Reason);
            await _pubSub.PublishAsync(NotificationMessage.Initialize(userToUpdate.Email!, userToUpdate.FirstName,
                EmailType.AccountSuspension, reason.GetDescription()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            // Log action
            await _pubSub.PublishAsync(AuditLog.Initialize(loggedInUserId, userToUpdate.Id, userToUpdate.Id.ToGuid(),
                AuditDomain.User, AuditAction.SuspendedAccount),
                routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new SuspendUserResponse
            {
                Response =
                new StringResponse { Message = "Account successfully suspended.", Status = 200 }
            };
        }

        /// <summary>
        /// Lift user suspension
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<LiftUserSuspensionResponse> LiftUserSuspension(LiftUserSuspensionRequest request, ServerCallContext context)
        {
            var loggedInUserId = CommonHelpers.GetUserId(context.GetHttpContext()?.User);
            var loggedInUser = await _userManager.FindByIdAsync(loggedInUserId) ?? 
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Access denied!!! You're not authorized to perform this action."));
            
            var roles = (await _userManager.GetRolesAsync(loggedInUser))?.ToList();
            if (roles == null || !roles.Contains(SystemRoles.SuperAdmin.GetDescription()) && !roles.Contains(SystemRoles.Admin.GetDescription()))
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Access denied!!! You're not authorized to perform this action."));
            }

            var userToUpdate = await _userManager.FindByIdAsync(request.Request.UserId) ??
                throw new RpcException(new Status(StatusCode.NotFound, "User not found"));
            
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

            return new LiftUserSuspensionResponse
            {
                Response =
                new StringResponse { Message = "Account successfully reactivated.", Status = 200 }
            };
        }

        /// <summary>
        /// Deactivate Account
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<DeactivateAccountResponse> DeactivateAccount(DeactivateAccountRequest request, ServerCallContext context)
        {
            var loggedInUserId = CommonHelpers.GetUserId(context.GetHttpContext()?.User);

            if (string.IsNullOrWhiteSpace(loggedInUserId) || !loggedInUserId.Equals(request.Request.UserId))
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Access denied!!! You're not authorized to perform this action."));
            }

            var user = await _userManager.FindByIdAsync(request.Request.UserId) ?? 
                throw new RpcException(new Status(StatusCode.NotFound, "User not found!"));
            
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

            return new DeactivateAccountResponse
            {
                Response =
                new StringResponse { Message = ResponseMessages.AccountDeactivated, Status = 200 }
            };
        }

        /// <summary>
        /// Request account Reactivate
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<RequestAccountReactivationResponse> RequestAccountReactivation(RequestAccountReactivationRequest request, ServerCallContext context)
        {
            var user = await _userManager.FindByEmailAsync(request.Request.Email) ??
                throw new RpcException(new Status(StatusCode.NotFound, ResponseMessages.UserNotFoundWithEmail));
            
            var otp = CommonHelpers.GenerateOtp();
            var (Hash, Salt) = CommonHelpers.HashOtp(otp);
            var otpEntry = user.Map(Hash, Salt, OtpType.AccountReactivation);

            await _crudKit.InsertAsync(otpEntry);

            // Email the OTP to the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!,
                user.FirstName, otp, OtpType.AccountReactivation.ToEmailType()),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new RequestAccountReactivationResponse
            {
                Response =
                new StringResponse { Message = ResponseMessages.AccountReactivationRequested, Status = 200 }
            };
        }

        /// <summary>
        /// Reactivate Account
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<ReactivateAccountResponse> ReactivateAccount(ReactivateAccountRequest request, ServerCallContext context)
        {
            if (string.IsNullOrWhiteSpace(request.Request.Otp) || string.IsNullOrWhiteSpace(request.Request.Email))
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, ResponseMessages.InvalidRequest));
            }

            var user = await _userManager.FindByEmailAsync(request.Request.Email) ??
                throw new RpcException(new Status(StatusCode.NotFound, ResponseMessages.UserNotFoundWithEmail));
            
            var otpEntry = await _crudKit
                .AsQueryable<OtpEntry>(o => o.UserId.Equals(user.Id) && o.Type == OtpType.AccountReactivation, true)
                .OrderByDescending(o => o.ExpiresAt).FirstOrDefaultAsync() ??
                    throw new RpcException(new Status(StatusCode.NotFound, ResponseMessages.InvalidOTP)); ;

            bool isValid = CommonHelpers.VerifyOtp(request.Request.Otp, otpEntry.OtpHash, otpEntry.OtpSalt)
                          && otpEntry.ExpiresAt.IsLaterThan(DateTime.UtcNow);
            if (!isValid)
            {
                throw new RpcException(new Status(StatusCode.DeadlineExceeded, ResponseMessages.OTPExpired));
            }

            user.UpdatedAt = DateTime.UtcNow;
            user.Status = UserStatus.Active;
            user.StatusChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Notify the user.
            await _pubSub.PublishAsync(NotificationMessage.Initialize(user.Email!,
                user.FirstName, EmailType.AccountReactivationNotification),
                routingKey: MQRoutingKey.AccountEmail.GetDescription());

            return new ReactivateAccountResponse
            {
                Response =
                new StringResponse { Message = ResponseMessages.AccountReactivated, Status = 200 }
            };
        }

        #region Private Methods
        private async Task<ApiBaseResponse> ValidateUser(LoginRequest request)
        {
            var validation = new LoginValidator().Validate(request);
            if (!validation.IsValid)
            {
                return new BadRequestResponse(validation.Errors.FirstOrDefault()?.ErrorMessage ?? "Invalid input");
            }

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

        private string CreateAccessToken(AppUser user, string[] roles, string validAudience)
        {
            var claims = GetClaims(user, roles);
            var creds = GetSigningCredentials();
            var jwt = GetJwtSecurityToken(claims, creds, DateTime.UtcNow, validAudience);

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private async Task<string> CreateAndSaveRefreshTokenAsync(string userId)
        {
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            var hash = ComputeHash(token);
            var record = new RefreshToken
            {
                Id = Guid.NewGuid(),
                TokenHash = hash,
                UserId = userId,
                ClientId = _config.ClientId,
                ExpiresAt = DateTimeOffset.UtcNow.Add(TimeSpan.FromDays(_config.Span))
            };

            await _crudKit.InsertAsync(record);
            return token;
        }

        private string ComputeHash(string token)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(bytes);
        }

        private SigningCredentials GetSigningCredentials()
        {
            var key = Encoding.UTF8.GetBytes(_config.PrivateKey);
            var secret = new SymmetricSecurityKey(key);
            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        }

        private List<Claim> GetClaims(AppUser user, string[] roles)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Iss, _config.Issuer),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("client_id", _config.ClientId) // optional
            };
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            return claims;
        }

        private JwtSecurityToken GetJwtSecurityToken(List<Claim> claims, SigningCredentials creds, DateTime now, string audience)
        {
            var jwt = new JwtSecurityToken(
                    issuer: _config.Issuer,
                    audience: audience,
                    claims: claims,
                    notBefore: now,
                    expires: now.AddHours(_config.Span),
                    signingCredentials: creds
                );
            return jwt;
        }

        public async Task<RefreshToken?> ValidateRefreshTokenAsync(string token)
        {
            var hash = ComputeHash(token);
            var rec = await _crudKit.AsQueryable<RefreshToken>(r => r.TokenHash == hash && r.ClientId == _config.ClientId, false)
                .FirstOrDefaultAsync();

            if (rec == null || rec.RevokedAt != null)
            {
                return null;
            }
            if (rec.ExpiresAt < DateTimeOffset.UtcNow)
            {
                rec.RevokedAt = DateTimeOffset.UtcNow;
                rec.IsDeprecated = true;
                await _crudKit.UpdateAsync(rec);
                return null;
            }
            return rec;
        }
        #endregion
    }
}