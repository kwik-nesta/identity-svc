using CSharpTypes.Extensions.Enumeration;
using DiagnosKit.Core.Configurations;
using EFCore.CrudKit.Library.Extensions;
using KwikNesta.Contracts.Enums;
using KwikNesta.Contracts.Settings;
using KwikNestaIdentity.Svc.Domain.Entities;
using KwikNestaIdentity.Svc.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Versioning;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text;

namespace KwikNestaIdentity.Svc.API.Extensions
{
    public static class ServiceExtensions
    {
        public static void ConfigureESSink(this IHostBuilder host,
                                           IConfiguration configuration)
        {
            host.ConfigureSerilogESSink(opt =>
            {
                var settings = configuration.GetSection("ElasticSearch")
                    .Get<ElasticSettings>() ?? throw new ArgumentNullException("ElasticSearch");

                opt.Url = settings.Url;
                opt.Username = settings.UserName;
                opt.Password = settings.Password;
                opt.IndexPrefix = settings.IndexPrefix;
                opt.IndexFormat = settings.IndexFormat;
            });
        }

        public static IServiceCollection ConfigureIdentityAndDbContext(this IServiceCollection services, IConfiguration configuration)
        {
            // Config
            var connectionString = configuration.GetConnectionString("DefaultConnection") ??
                throw new InvalidOperationException("Connection string not set.");

            // EF + Identity
            services.AddDbContext<AppDbContext>(options =>
                options.UseNpgsql(connectionString));
            
            services.AddIdentity<AppUser, IdentityRole>(options =>
            {
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 8;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.SignIn.RequireConfirmedEmail = true;
                options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();

            services.ConfigureEFCoreDataForge<AppDbContext>(false);
            return services;
        }

        public static IServiceCollection ConfigureJwt(this IServiceCollection services, IConfiguration configuration)
        {
            var section = configuration.GetSection("Jwt");
            services.Configure<Jwt>(section);
            var jwtOptions = section.Get<Jwt>() ??
                throw new ArgumentNullException("JWT Config can not be null");

            services.AddAuthentication(opt =>
            {
                opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtOptions.Issuer!,

                    ValidateAudience = true,
                    ValidAudience = jwtOptions.Audience,

                    ValidateLifetime = true,

                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.PrivateKey!))
                };
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        if (context != null)
                        {
                            var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<AppUser>>();
                            var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                            if (string.IsNullOrEmpty(userId))
                            {
                                context.Fail("Forbidden: Invalid identifier");
                                return;
                            }

                            var user = await userManager.FindByIdAsync(userId);
                            if (user != null)
                            {
                                if (user.Status != UserStatus.Active && user.StatusChangedAt.HasValue &&
                                user.StatusChangedAt.Value < DateTime.UtcNow)
                                {
                                    context.Fail($"Forbidden: Your account has been {user.Status.GetDescription()}");
                                }
                            }
                            else
                            {
                                context.Fail("Forbidden: User not found");
                            }
                        }
                    }
                };

            });
            return services;
        }

        public static IServiceCollection ConfigureCors(this IServiceCollection services) =>
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy", builder =>
                    builder.WithOrigins()
                        .AllowCredentials()
                        .AllowAnyMethod()
                        .AllowAnyHeader());
            });

        public static IServiceCollection ConfigureApiVersioning(this IServiceCollection services)
        {
            return services.AddApiVersioning(opt =>
            {
                opt.ReportApiVersions = true;
                opt.AssumeDefaultVersionWhenUnspecified = true;
                opt.DefaultApiVersion = new ApiVersion(1, 0);
                opt.ApiVersionReader = ApiVersionReader.Combine(
                    new HeaderApiVersionReader("api-version"),
                    new HeaderApiVersionReader("X-Version"),
                    new UrlSegmentApiVersionReader());
            });
        }

        public static IServiceCollection ConfigureSwaggerDocs(this IServiceCollection services)
        {
            return services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "Kwik Nesta Identity Service",
                    Version = "v1",
                    Description = "Kwik Nesta Identity",
                    Contact = new OpenApiContact
                    {
                        Name = "Kwik Nesta Inc.",
                        Email = "info@kwik-nesta.com",
                        Url = new Uri("https://kwik-nesta.com")
                    }
                });
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "Kwik Nesta Identity Service Api"
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    Array.Empty<string>()
                }});
            });
        }
    }
}
