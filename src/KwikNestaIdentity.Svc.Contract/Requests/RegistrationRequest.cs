using KwikNestaIdentity.Svc.Domain.Enums;

namespace KwikNestaIdentity.Svc.Contract.Requests
{
    public class RegistrationRequest
    {
        public string FirstName { get; init; } = string.Empty;
        public string LastName { get; init; } = string.Empty;
        public string? MiddleName { get; init; }
        public string Email { get; init; } = string.Empty;
        public string PhoneNumber { get; init; } = string.Empty;
        public string Password { get; init; } = string.Empty;
        public string ConfirmPassword { get; init; } = string.Empty;
        public Gender Gender { get; set; } = Gender.Others;
        public SystemRoles Role { get; init; } = SystemRoles.Tenant;
    }
}