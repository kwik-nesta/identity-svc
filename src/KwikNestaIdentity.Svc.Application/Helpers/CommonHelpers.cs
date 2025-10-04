using API.Common.Response.Model.Exceptions;
using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.List;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Contract.Protos;
using KwikNestaIdentity.Svc.Domain.Entities;
using KwikNestaIdentity.Svc.Domain.Enums;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace KwikNestaIdentity.Svc.Application.Helpers
{
    public class CommonHelpers
    {
        public static void GetStatusResponse(UserStatus status)
        {
            switch (status)
            {
                case UserStatus.PendingVerification:
                    throw new ForbiddenException("You can't login at the moment. Please confirm your email.");
                case UserStatus.Deactivated:
                    throw new ForbiddenException("Your account has been suspended. Please contact support.");
                case UserStatus.Suspended:
                    throw new ForbiddenException("Your account has been suspended. Please contact support.");
                default:
                    break;
            }
        }

        public static async Task<List<SystemRoles>> GetUserRoles(UserManager<AppUser> userManager, ClaimsPrincipal? userClaim)
        {
            var roles = new List<SystemRoles>();
            var userId = GetUserId(userClaim);
            if (userId.IsNotNullOrEmpty())
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return roles;
                }

                return (await userManager.GetRolesAsync(user)).ToList().ParseValues<SystemRoles>();
            }

            return roles;
        }

        public static string GetUserId(ClaimsPrincipal? userClaim)
        {
            return userClaim?.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        }

        public static string GenerateOtp(int length = 5)
        {
            if (length <= 0) throw new ArgumentException("OTP length must be positive.");

            // Use a secure random number generator
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            int randomNumber = BitConverter.ToInt32(bytes, 0) & 0x7FFFFFFF; // ensure non-negative

            // Generate a number with the desired length
            int otpValue = randomNumber % (int)Math.Pow(10, length);

            // Pad with leading zeros if necessary (e.g., "00429")
            return otpValue.ToString(new string('0', length));
        }

        public static (string Hash, string Salt) HashOtp(string otp)
        {
            // Generate random salt
            byte[] saltBytes = RandomNumberGenerator.GetBytes(16);

            using var hmac = new HMACSHA256(saltBytes);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(otp));

            return (Convert.ToBase64String(hash), Convert.ToBase64String(saltBytes));
        }

        public static bool VerifyOtp(string otp, string storedHash, string storedSalt)
        {
            var saltBytes = Convert.FromBase64String(storedSalt);

            using var hmac = new HMACSHA256(saltBytes);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(otp));

            var computedHash = Convert.ToBase64String(hash);
            return computedHash == storedHash;
        }
    }
}
