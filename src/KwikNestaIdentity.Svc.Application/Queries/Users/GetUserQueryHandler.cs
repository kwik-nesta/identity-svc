using API.Common.Response.Model.Exceptions;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace KwikNestaIdentity.Svc.Application.Queries.Users
{
    public class GetUserQueryHandler : IRequestHandler<GetUserQuery, CurrentUserDto>
    {
        private readonly UserManager<AppUser> _userManager;

        public GetUserQueryHandler(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<CurrentUserDto> Handle(GetUserQuery request, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByIdAsync(request.Id) ?? 
                throw new NotFoundException("User information not found.");

            return user.MapData();
        }
    }
}
