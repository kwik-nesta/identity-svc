using KwikNesta.Contracts.Models;
using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Queries.Users
{
    public record GetUsersQuery(List<string> Ids) : IRequest<ApiResult<List<CurrentUserDto>>>;
}
