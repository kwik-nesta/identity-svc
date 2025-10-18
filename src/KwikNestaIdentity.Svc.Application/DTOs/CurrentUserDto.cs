namespace KwikNestaIdentity.Svc.Application.DTOs
{
    public record CurrentUserDto
    {

        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? MiddleName { get; set; }
        public string? PhoneNumber { get; set; }
        public string Gender { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
    }
}