using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Domain.Enums;
using MediatR;

namespace KwikNestaIdentity.Svc.Application.Commands.Register
{
    public record RegisterCommand : IRequest<RegisterResponseDto>
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? MiddleName { get; set; }
        public string Email { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string ConfirmPassword { get; set; } = string.Empty;
        public Gender Gender { get; set; }
        public SystemRoles Role { get; set; }
    }
}