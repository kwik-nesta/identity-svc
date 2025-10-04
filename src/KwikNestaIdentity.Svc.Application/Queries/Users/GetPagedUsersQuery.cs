using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Domain.Enums;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Queries.Users
{
    public class GetPagedUsersQuery : PageQuery, IRequest<PagedUsersResponseDto>
    {
        public string Search { get; set; } = string.Empty;
        public Gender? Gender { get; set; }
        public UserStatus? Status { get; set; }
    }
}
