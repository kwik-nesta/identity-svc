using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Queries.Users
{
    public class GetPagedUsersQuery : PageQuery, IRequest<ApiResult<PagedUsersResponseDto>>
    {
        public string Search { get; set; } = string.Empty;
        public Gender? Gender { get; set; }
        public UserStatus? Status { get; set; }
    }
}
