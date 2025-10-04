using API.Common.Response.Model.Exceptions;
using CSharpTypes.Extensions.Enumeration;
using KwikNesta.Contracts.Extensions;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Domain.Entities;
using KwikNestaIdentity.Svc.Domain.Enums;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace KwikNestaIdentity.Svc.Application.Queries.Users
{
    public class GetPagedUsersQueryHandler : IRequestHandler<GetPagedUsersQuery, PagedUsersResponseDto>
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly ClaimsPrincipal? _claim;

        public GetPagedUsersQueryHandler(UserManager<AppUser> userManager,
                                         IHttpContextAccessor accessor)
        {
            _userManager = userManager;
            _claim = accessor.HttpContext?.User;
        }

        public async Task<PagedUsersResponseDto> Handle(GetPagedUsersQuery request, CancellationToken cancellationToken)
        {
            if (!(_claim?.IsInRole(SystemRoles.Admin.GetDescription()) ?? false) &&
                !(_claim?.IsInRole(SystemRoles.SuperAdmin.GetDescription()) ?? false))
            {
                throw new ForbiddenException("Access denied!!! You're not authorized to perform this action.");
            }

            var users = _userManager.Users
                .OrderByDescending(c => c.CreatedAt)
                .Filter(request)
                .Search(request.Search);

            var pagedData = await Task.Run(() => users.Paginate(request.Page, request.PageSize));
            return new PagedUsersResponseDto
            {
                Meta = new PageMetaDto
                {
                    Page = pagedData.CurrentPage,
                    Size = pagedData.PageCount,
                    TotalCount = pagedData.ItemCount,
                    HasNext = pagedData.HasNext,
                    HasPrevious = pagedData.HasPrevious
                },
                Users = pagedData.Items.Select(u => u.MapData()).ToList()
            };
        }
    }
}
