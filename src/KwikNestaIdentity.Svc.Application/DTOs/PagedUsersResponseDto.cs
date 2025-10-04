namespace KwikNestaIdentity.Svc.Application.DTOs
{
    public class PagedUsersResponseDto
    {
        public PageMetaDto Meta { get; set; } = new();
        public List<CurrentUserDto> Users { get; set; } = [];
    }
}
