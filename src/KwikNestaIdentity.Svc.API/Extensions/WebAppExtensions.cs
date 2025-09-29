using CSharpTypes.Extensions.Enumeration;
using CSharpTypes.Extensions.String;
using KwikNestaIdentity.Svc.Domain.Entities;
using KwikNestaIdentity.Svc.Domain.Enums;
using KwikNestaIdentity.Svc.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace KwikNestaIdentity.Svc.API.Extensions
{
    public static class WebAppExtensions
    {
        internal static void RunMigrations(this WebApplication app, bool alwaysRun)
        {
            if (app.Environment.IsDevelopment() || alwaysRun)
            {
                using (var scope = app.Services.CreateScope())
                {
                    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                    db.Database.Migrate();
                }
            }
        }
        internal static async Task SeedInitialData(this WebApplication app, ILogger<Program> logger)
        {
            using var scope = app.Services.CreateScope();
            await SeedAdminUser(scope, logger);
        }

        private static async Task SeedAdminUser(IServiceScope scope, ILogger<Program> logger)
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
            var config = scope.ServiceProvider.GetRequiredService<IConfiguration>();
            if (userManager == null || config == null)
            {
                logger.LogWarning("UserManager and/or IConfiguration is null");
                return;
            }

            var email = config["AdminUser:Email"];
            var password = config["AdminUser:Password"];
            var phone = config["AdminUser:PhoneNumber"];
            if (email!.IsNullOrEmpty() || password!.IsNullOrEmpty() || phone!.IsNullOrEmpty())
            {
                logger.LogWarning("Email, phone, and/or password is null or empty string");
                return;
            }

            var exists = userManager.Users.Any(u => u.Email != null && u.Email.Equals(email));
            if (!exists)
            {
                logger.LogInformation($"Starting user seeding...");
                var user = new AppUser
                {
                    FirstName = "System",
                    LastName = "Admin",
                    Email = email,
                    PhoneNumber = phone,
                    UserName = email,
                    Gender = Gender.Male,
                    Status = UserStatus.Active,
                    EmailConfirmed = true,
                    PhoneNumberConfirmed = true
                };

                var result = await userManager.CreateAsync(user, password!);
                if (!result.Succeeded)
                {
                    logger.LogError(result.Errors.FirstOrDefault()?.Description ?? "Could not create user");
                    return;
                }

                var roleResult = await userManager.AddToRoleAsync(user, SystemRoles.SuperAdmin.GetDescription());
                if (!roleResult.Succeeded)
                {
                    await userManager.DeleteAsync(user);
                    logger.LogError(roleResult.Errors.FirstOrDefault()?.Description ?? "Could not add user to role");
                    return;
                }

                logger.LogInformation("User registration successful");
                return;
            }

            logger.LogInformation("Seeding skipped.... User already exist in the database.");
        }
    }
}
