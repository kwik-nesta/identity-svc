using CSharpTypes.Extensions.Enumeration;
using KwikNesta.Contracts.Enums;
using KwikNestaIdentity.Svc.Application.Commands.Register;
using KwikNestaIdentity.Svc.Application.Commands.UpdateBasicDetails;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Domain.Entities;

namespace KwikNestaIdentity.Svc.Application.Extensions
{
    internal static class ObjectMapper
    {
        public static AppUser Map(this RegisterCommand request)
        {
            return new AppUser
            {
                FirstName = request.FirstName,
                LastName = request.LastName,
                OtherName = request.MiddleName,
                Email = request.Email,
                PhoneNumber = request.PhoneNumber,
                UserName = request.Email,
                Gender = request.Gender
            };
        }

        public static OtpEntry Map(this AppUser user,
                                   string hash,
                                   string salt,
                                   OtpType otpType = OtpType.AccountVerification,
                                   string? token = null,
                                   int span = 10)
        {
            return new OtpEntry
            {
                UserId = user.Id,
                OtpHash = hash,
                OtpSalt = salt,
                ExpiresAt = DateTime.UtcNow.AddMinutes(span),
                Type = otpType,
                Token = token
            };
        }

        public static CurrentUserDto MapData(this AppUser user)
        {
            return new CurrentUserDto
            {
                Id = user.Id,
                Email = user.Email!,
                FirstName = user.FirstName,
                LastName = user.LastName,
                MiddleName = user.OtherName ?? string.Empty,
                PhoneNumber = user.PhoneNumber,
                Gender = user.Gender.GetDescription(),
                Status = user.Status.GetDescription()
            };
        }

        public static AppUser Map(this AppUser user, UpdateBasicUserDetailsCommand request)
        {
            user.FirstName = request.FirstName;
            user.LastName = request.LastName;
            user.OtherName = request.OtherName;
            user.Gender = request.Gender;
            user.UpdatedAt = DateTime.UtcNow;

            return user;
        }
    }
}
