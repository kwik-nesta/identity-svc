using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Queries.Users
{
    public record GetUserQuery(string Id) : IRequest<CurrentUserDto>;
}
