namespace KwikNestaIdentity.Svc.Contract.DTOs
{
    public class LoginTokenDto
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
    }
}
