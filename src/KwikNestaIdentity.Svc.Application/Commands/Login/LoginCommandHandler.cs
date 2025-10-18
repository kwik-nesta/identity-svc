using API.Common.Response.Model.Exceptions;
using CrossQueue.Hub.Services.Interfaces;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.Guid;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNesta.Contracts.Commands;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Application.Validations;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace KwikNestaIdentity.Svc.Application.Commands.Login
{
    public class LoginCommandHandler : IRequestHandler<LoginCommand, ApiResult<LoginResponseDto>>
    {
        private readonly IRabbitMQPubSub _pubSub;
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IEFCoreCrudKit _crudKit;
        private readonly Jwt _config;

        public LoginCommandHandler(IRabbitMQPubSub pubSub,
                           IOptions<Jwt> config,
                           UserManager<AppUser> userManager,
                           SignInManager<AppUser> signInManager,
                           IEFCoreCrudKit crudKit)
        {
            _pubSub = pubSub;
            _userManager = userManager;
            _signInManager = signInManager;
            _crudKit = crudKit;
            _config = config.Value;
        }

        public async Task<ApiResult<LoginResponseDto>> Handle(LoginCommand request, CancellationToken cancellationToken)
        {
            var (User, Roles) = await ValidateUser(request);
            
            var accessToken = AuthHelpers.CreateAccessToken(User, Roles, _config);
            var (Token, RefreshToken) = AuthHelpers.CreateRefreshToken(User.Id, _config);

            User.UpdatedAt = DateTime.UtcNow;
            User.LastLogin = DateTime.UtcNow;

            await _userManager.UpdateAsync(User);
            await _crudKit.InsertAsync(RefreshToken, cancellation: cancellationToken);

            await _pubSub.PublishAsync(new AuditCommand
            {
                PerformedBy = User.Id,
                DomainId = User.Id.ToGuid(),
                Domain = AuditDomain.Identity,
                Action = AuditAction.LoggedIn,
                TargetId = User.Id
            }, routingKey: MQRoutingKey.AuditTrails.GetDescription());

            return new ApiResult<LoginResponseDto>(new LoginResponseDto(accessToken, Token));
        }

        #region Private Methods
        private async Task<(AppUser User, string[] Roles)> ValidateUser(LoginCommand request)
        {
            var validation = new LoginValidator().Validate(request);
            if (!validation.IsValid)
            {
                throw new BadRequestException(validation.Errors.FirstOrDefault()?.ErrorMessage ?? "Invalid input");
            }

            var user = await _userManager.FindByNameAsync(request.UserName);
            if (user == null)
            {
                throw new NotFoundException("User not found");
            }

            if (!user.EmailConfirmed || user.Status != UserStatus.Active)
            {
                CommonHelpers.GetStatusResponse(user.Status);
            }

            var check = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            if (!check.Succeeded)
            {
                throw new ForbiddenException("Wrong password");
            }

            var roles = (await _userManager.GetRolesAsync(user)).ToArray();
            if (roles == null || roles.Length == 0)
            {
                throw new UnauthorizedException("User have no assigned role.");
            }

            return (user, roles);
        }

        #endregion
    }
}
