using EFCore.CrudKit.Library.Models;
using KwikNesta.Contracts.Enums;

namespace KwikNestaIdentity.Svc.Domain.Entities
{
    public class OtpEntry : EntityBase
    {
        public string UserId { get; set; } = string.Empty;
        public string OtpHash { get; set; } = string.Empty;
        public string OtpSalt { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public OtpType Type { get; set; } = OtpType.AccountVerification;
        public string? Token { get; set; }
        public int Attempts { get; set; }
    }
}
