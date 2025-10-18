using CSharpTypes.Extensions.Enumeration;
using KwikNesta.Contracts.Enums;

namespace KwikNestaIdentity.Svc.Contract.DTOs
{
    public class UserLeanDto
    {
        public string Id { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? MiddleName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Gender { get; set; } = string.Empty;
        public UserStatus Status { get; set; }
        public string StatusDescription => Status.GetDescription();
        public string PhoneNumber { get; set; } = string.Empty;
    }
}
