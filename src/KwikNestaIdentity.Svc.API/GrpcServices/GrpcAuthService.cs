using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using KwikNesta.Contracts.Enums;
using KwikNestaIdentity.Svc.Application.Commands.Deactivations;
using KwikNestaIdentity.Svc.Application.Commands.Login;
using KwikNestaIdentity.Svc.Application.Commands.PasswordRequests;
using KwikNestaIdentity.Svc.Application.Commands.Reactivations;
using KwikNestaIdentity.Svc.Application.Commands.RefreshTokens;
using KwikNestaIdentity.Svc.Application.Commands.Register;
using KwikNestaIdentity.Svc.Application.Commands.Suspension;
using KwikNestaIdentity.Svc.Application.Commands.Verification;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Contract.Protos;
using MediatR;
using Empty = Google.Protobuf.WellKnownTypes.Empty;

namespace KwikNestaIdentity.Svc.API.GrpcServices
{
    public class GrpcAuthService : AuthenticationService.AuthenticationServiceBase
    {
        private readonly IMediator _mediator;

        public GrpcAuthService(IMediator mediator)
        {
            _mediator = mediator;
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
            var response = await _mediator.Send(new LoginCommand
            {
                UserName = request.UserName,
                Password = request.Password
            });

            return new LoginResponse
            {
                Tokens = new TokenResponse
                {
                    AccessToken = response.AccessToken,
                    RefreshToken = response.RefreshToken
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
            var response = await _mediator.Send(new RegisterCommand
            {
                FirstName = request.FirstName,
                LastName = request.LastName,
                MiddleName = request.MiddleName,
                Email = request.Email,
                PhoneNumber = request.PhoneNumber,
                Password = request.Password,
                ConfirmPassword = request.ConfirmPassword,
                Gender = EnumMapper.Map<GrpcGender, Gender>(request.Gender),
                Role = EnumMapper.Map<GrpcSystemRole, SystemRoles>(request.SystemRole)
            });

            return new RegisterResponse
            {
                Email = response.Email,
                Message = response.Message
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
            var response = await _mediator.Send(new RefreshTokenCommand
            {
                RefreshToken = request.RefreshToken
            });

            return new RefreshTokenResponse
            {
                Token = new TokenResponse
                {
                    AccessToken = response.AccessToken,
                    RefreshToken = response.RefreshToken
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
            var response = await _mediator.Send(new VerificationCommand
            {
                Email = request.Request.Email,
                Otp = request.Request.Otp
            });

            return new VerifyAccountResponse
            {
                Response = new StringResponse
                {
                    Message = response.Message,
                    Status = response.Status
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
            var response = await _mediator.Send(new ResendOtpCommand
            {
                Email = request.Email,
                Type = EnumMapper.Map<GrpcOtpType, OtpType>(request.Type)
            });

            return new ResendOtpResponse
            {
                Response = new StringResponse
                {
                    Message = response.Message,
                    Status = response.Status
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
            var response = await _mediator.Send(new PasswordResetCommand
            {
                Email = request.Request.Email
            });

            return new PasswordResetResponse
            {
                Response = new StringResponse
                {
                    Message = response.Message,
                    Status = response.Status
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
            var response = await _mediator.Send(new ChangeForgotPasswordCommand
            {
                Email = request.Request.Email,
                Otp = request.Request.Otp,
                NewPassword = request.NewPassword,
                ConfirmNewPassword = request.ConfirmPassword
            });

            return new ChangeForgotPasswordResponse
            {
                Response = new StringResponse
                {
                    Message = response.Message,
                    Status = response.Status
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
            var response = await _mediator.Send(new ChangePasswordCommand
            {
                NewPassword = request.NewPassword,
                CurrentPassword = request.CurrentPassword,
                ConfirmNewPassword = request.ConfirmNewPassword
            });

            return new ChangePasswordResponse
            {
                Response = new StringResponse
                {
                    Message = response.Message,
                    Status = response.Status
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
            var response = await _mediator.Send(new SuspendUserCommand
            {
                UserId = request.UserId,
                Reason = EnumMapper.Map<GrpcSuspensionReason, SuspensionReasons>(request.Reason)
            });

            return new SuspendUserResponse
            {
                Response =
                new StringResponse { Message = response.Message, Status = response.Status }
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
            var response = await _mediator.Send(new LiftSuspensionCommand
            {
                UserId = request.Request.UserId
            });

            return new LiftUserSuspensionResponse
            {
                Response =
                new StringResponse { Message = response.Message, Status = response.Status }
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
            var response = await _mediator.Send(new DeactivationCommand
            {
                UserId = request.Request.UserId
            });

            return new DeactivateAccountResponse
            {
                Response =
                new StringResponse { Message = response.Message, Status = response.Status }
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
            var response = await _mediator.Send(new ReactivationRequestCommand
            {
                Email = request.Request.Email
            });

            return new RequestAccountReactivationResponse
            {
                Response =
                new StringResponse { Message = response.Message, Status = response.Status }
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
            var response = await _mediator.Send(new ReactivationCommand
            {
                Email = request.Request.Email,
                Otp = request.Request.Otp
            });

            return new ReactivateAccountResponse
            {
                Response =
                new StringResponse { Message = response.Message, Status = response.Status }
            };
        }
    }
}