namespace KwikNestaIdentity.Svc.Contract.Requests
{
    public record LoginRequest
    {
        public string UserName { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}