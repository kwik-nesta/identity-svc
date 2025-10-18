using EFCore.CrudKit.Library.Models;

namespace KwikNestaIdentity.Svc.Domain.Entities
{
    public class RefreshToken : EntityBase
    {
        public string TokenHash { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public DateTimeOffset ExpiresAt { get; set; }
        public DateTimeOffset? RevokedAt { get; set; }
        public string ReplacedByTokenHash { get; set; } = string.Empty;
    }
}