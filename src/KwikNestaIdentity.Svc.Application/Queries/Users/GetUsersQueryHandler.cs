using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace KwikNestaIdentity.Svc.Application.Queries.Users
{
    public class GetUsersQueryHandler : IRequestHandler<GetUsersQuery, ApiResult<List<CurrentUserDto>>>
    {
        private readonly UserManager<AppUser> _userManager;

        public GetUsersQueryHandler(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<ApiResult<List<CurrentUserDto>>> Handle(GetUsersQuery request, CancellationToken cancellationToken)
        {
            var users = await _userManager.Users
               .Where(u => request.Ids.Contains(u.Id))
               .ToListAsync(cancellationToken);

            return new ApiResult<List<CurrentUserDto>>(users.Select(u => u.MapData()).ToList());
        }
    }
}
