using CSharpTypes.Extensions.Enumeration;
using KwikNesta.Contracts.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace KwikNestaIdentity.Svc.Infrastructure.Configurations
{
    public class RoleConfiguration : IEntityTypeConfiguration<IdentityRole>
    {
        public void Configure(EntityTypeBuilder<IdentityRole> builder)
        {
            builder.HasData(
                new IdentityRole
                {
                    Id = new Guid("27aec839-5fa7-4dab-8295-c5fb64dd0c64").ToString(),
                    Name = SystemRoles.SuperAdmin.GetDescription(),
                    NormalizedName = SystemRoles.SuperAdmin.GetDescription().ToUpper(),
                    ConcurrencyStamp = "0a756968-67bd-4e6e-9863-bd823cf36619"
                },
                new IdentityRole
                {
                    Id = new Guid("55d6e525-9fc7-46e7-99e3-9ce309c66444").ToString(),
                    Name = SystemRoles.Admin.GetDescription(),
                    NormalizedName = SystemRoles.Admin.GetDescription().ToUpper(),
                    ConcurrencyStamp = "ea7e6ef6-a7eb-4143-91b2-37a858da1f16"
                },
                new IdentityRole
                {
                    Id = new Guid("ae27c839-5fa7-d4ab-9582-c5fb64ddc046").ToString(),
                    Name = SystemRoles.LandLord.GetDescription(),
                    NormalizedName = SystemRoles.LandLord.GetDescription().ToUpper(),
                    ConcurrencyStamp = "89056968-67bd-6e4e-9863-bfa23c36f619"
                },
                new IdentityRole
                {
                    Id = new Guid("e647e525-c7f9-46e7-e3e3-2face309c664").ToString(),
                    Name = SystemRoles.Tenant.GetDescription(),
                    NormalizedName = SystemRoles.Tenant.GetDescription().ToUpper(),
                    ConcurrencyStamp = "767e6e6f-a7eb-4143-91b2-7a3858ae116f"
                },
                new IdentityRole
                {
                    Id = new Guid("52544e6e-9fc7-46e7-99e3-9c664ff9ce30").ToString(),
                    Name = SystemRoles.Agent.GetDescription(),
                    NormalizedName = SystemRoles.Agent.GetDescription().ToUpper(),
                    ConcurrencyStamp = "6ef6677e-a7eb-4143-91b2-58a37a8e1f16"
                });
        }
    }
}