namespace KwikNestaIdentity.Svc.Application.DTOs
{
    public class PageMetaDto
    {
        public int Page { get; set; }
        public int Size { get; set; }
        public int TotalCount { get; set; }
        public bool HasNext { get; set; }
        public bool HasPrevious { get; set; }
    }
}