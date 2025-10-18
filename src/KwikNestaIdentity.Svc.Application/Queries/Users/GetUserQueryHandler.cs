using API.Common.Response.Model.Exceptions;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace KwikNestaIdentity.Svc.Application.Queries.Users
{
    public class GetUserQueryHandler : IRequestHandler<GetUserQuery, ApiResult<CurrentUserDto>>
    {
        private readonly UserManager<AppUser> _userManager;

        public GetUserQueryHandler(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<ApiResult<CurrentUserDto>> Handle(GetUserQuery request, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByIdAsync(request.Id) ?? 
                throw new NotFoundException("User information not found.");

            return new ApiResult<CurrentUserDto>(user.MapData());
        }
    }
}
