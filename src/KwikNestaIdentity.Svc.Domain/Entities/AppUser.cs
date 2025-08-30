using KwikNestaIdentity.Svc.Domain.Enums;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace KwikNestaIdentity.Svc.Domain.Entities
{
    public class AppUser : IdentityUser
    {
        [Required]
        public string FirstName { get; set; } = string.Empty;
        [Required]
        public string LastName { get; set; } = string.Empty;
        public string? OtherName { get; set; }
        public Gender Gender { get; set; } = Gender.Others;
        public UserStatus Status { get; set; } = UserStatus.PendingVerification;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastLogin { get; set; }
        public DateTime? StatusChangedAt { get; set; }
    }
}