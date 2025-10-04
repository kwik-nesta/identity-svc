namespace KwikNestaIdentity.Svc.Application.DTOs
{
    public record GenericResponseDto(int Status, string Message, bool Successful = true);
}
