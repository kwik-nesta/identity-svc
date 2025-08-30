using KwikNesta.Contracts.Enums;

namespace KwikNestaIdentity.Svc.Contract.Requests
{
    public class OtpResendRequest
    {
        public string Email { get; set; } = string.Empty;
        public OtpType Type { get; set; } = OtpType.AccountVerification;
    }
}
