using API.Common.Response.Model.Exceptions;
using CSharpTypes.Extensions.Enumeration;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Application.Helpers;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace KwikNestaIdentity.Svc.Application.Queries.LoggedInUser
{
    public class CurrentUserQueryHandler : IRequestHandler<CurrentUserQuery, CurrentUserDto>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly ClaimsPrincipal? _claim;

        public CurrentUserQueryHandler(UserManager<AppUser> userManager, 
                                       IHttpContextAccessor contextAccessor)
        {
            _userManager = userManager;
            _claim = contextAccessor.HttpContext?.User;
        }

        public async Task<CurrentUserDto> Handle(CurrentUserQuery request, CancellationToken cancellationToken)
        {
            var userId = CommonHelpers.GetUserId(_claim);
            var user = await _userManager.FindByIdAsync(userId) ??
                throw new NotFoundException("User information not found.");

            return user.MapData();
        }
    }
}
