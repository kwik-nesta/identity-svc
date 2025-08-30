using KwikNestaIdentity.Svc.Domain.Enums;

namespace KwikNestaIdentity.Svc.Contract.Requests
{
    public class UpdateUserBasicDetailsRequest
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string OtherName { get; set; } = string.Empty;
        public Gender Gender { get; set; }
    }
}
