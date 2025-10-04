namespace KwikNestaIdentity.Svc.Application.DTOs
{
    public record LoginResponseDto(string AccessToken, string RefreshToken);
}
