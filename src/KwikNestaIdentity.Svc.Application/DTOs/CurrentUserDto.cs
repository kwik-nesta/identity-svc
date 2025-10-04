using System.Text.Json.Serialization;

namespace KwikNestaIdentity.Svc.Application.DTOs
{
    public record CurrentUserDto
    {
        private string _name = "";

        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FullName
        {
            get => _name;
            set
            {
                var middleName = string.IsNullOrWhiteSpace(MiddleName) ?
                    "" : MiddleName.Substring(0, 1).Append('.');

                _name = $"{LastName} {FirstName} {middleName}"
                    .Trim();
            }
        }

        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? MiddleName { get; set; }
        public string? PhoneNumber { get; set; }
        public string Gender { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
    }
}