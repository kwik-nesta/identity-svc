using KwikNesta.Contracts.Enums;
using KwikNestaIdentity.Svc.Contract.Protos;

namespace KwikNestaIdentity.Svc.Application.Validations
{
    internal class ValidationExtensions
    {
        private static readonly List<GrpcSystemRole> _adminRoles = new List<GrpcSystemRole>
        {
            GrpcSystemRole.SuperAdmin, GrpcSystemRole.Admin
        };

        internal static bool IsAValidRole(SystemRoles role)
        {
            return role != SystemRoles.None;
        }

        internal static bool IsAMatch(string password, string comparePassword)
        {
            return password.ToLower().Equals(comparePassword.ToLower());
        }

        internal static bool IsAValidStatusForUpdate(UserStatus status)
        {
            return status != UserStatus.PendingVerification;
        }
    }
}
