using KwikNestaIdentity.Svc.Application.Queries.Users;
using KwikNestaIdentity.Svc.Contract.Protos;
using KwikNestaIdentity.Svc.Domain.Entities;
using KwikNestaIdentity.Svc.Domain.Enums;

namespace KwikNestaIdentity.Svc.Application.Extensions
{
    public static class QueryFilterExtensions
    {
        public static IEnumerable<AppUser> Search(this IEnumerable<AppUser> users, string search)
        {
            if (string.IsNullOrWhiteSpace(search))
            {
                return users;
            }

            return users.Where(u => u.FirstName.Contains(search, StringComparison.OrdinalIgnoreCase) || 
                u.LastName.Contains(search, StringComparison.OrdinalIgnoreCase) || 
                (!string.IsNullOrEmpty(u.Email) && u.Email.Contains(search, StringComparison.OrdinalIgnoreCase)) || 
                (!string.IsNullOrEmpty(u.OtherName) && u.OtherName.Contains(search, StringComparison.OrdinalIgnoreCase)));
        }

        public static IEnumerable<AppUser> Filter(this IEnumerable<AppUser> users, GetPagedUsersQuery request)
        {
            if (request.Gender.HasValue)
            {
                users = users.Where(u => u.Gender == request.Gender.Value);
            }
            if (request.Status.HasValue)
            {
                users = users.Where(u => u.Status == request.Status.Value);
            }

            return users;
        }
    }
}
