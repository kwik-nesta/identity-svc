using KwikNestaIdentity.Svc.Application.DTOs;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Queries.LoggedInUser
{
    public record CurrentUserQuery : IRequest<CurrentUserDto>
    {

    }
}