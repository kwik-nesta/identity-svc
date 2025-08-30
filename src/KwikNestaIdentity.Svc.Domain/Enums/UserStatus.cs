using System.ComponentModel;

namespace KwikNestaIdentity.Svc.Domain.Enums
{
    public enum UserStatus
    {
        [Description("Pending Verification")]
        PendingVerification,
        [Description("Active")]
        Active,
        [Description("Deactivated")]
        Deactivated,
        [Description("Suspended")]
        Suspended
    }
}
