using KwikNestaIdentity.Svc.Domain.Enums;

namespace KwikNestaIdentity.Svc.Contract.Requests
{
    public class UserSuspensionRequest
    {
        public string UserId { get; set; } = string.Empty;
        public SuspensionReasons Reason { get; set; }
    }
}
