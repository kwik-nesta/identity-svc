using CrossQueue.Hub.Shared.Extensions;
using DiagnosKit.Core.Configurations;
using DiagnosKit.Core.Extensions;
using DiagnosKit.Core.Logging;
using KwikNestaIdentity.Svc.API.Extensions;
using KwikNestaIdentity.Svc.API.Filters;
using KwikNestaIdentity.Svc.Application.Services;
using System.Net;

SerilogBootstrapper.UseBootstrapLogger();
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services
    .ConfigureIdentityAndDbContext(builder.Configuration)
    .AddCrossQueueHubRabbitMqBus(builder.Configuration)
    .ConfigureJwt(builder.Configuration)
    .AddDiagnosKitObservability(serviceName: builder.Environment.ApplicationName, serviceVersion: "1.0.0")
    .AddLoggerManager();

builder.Host.ConfigureSerilogESSink();
builder.Services.AddAuthorization();
builder.Services.AddGrpc(options =>
{
    options.Interceptors.Add<GrpcExceptionInterceptor>();
});

var app = builder.Build();

var logger = app.Services.GetRequiredService<ILogger<Program>>();
app.UseDiagnosKitPrometheus()
    .UseDiagnosKitErrorHandler()
    .UseDiagnosKitLogEnricher();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// Map gRPC service
app.MapGrpcService<GrpcAppUserService>();
app.MapGrpcService<GrpcAuthenticationService>();
app.MapGet("/", () => new
{
    Status = HttpStatusCode.OK,
    Message = "Kwik Nesta Identity Service is running..."
});

app.RunMigrations(true);
await app.SeedInitialData(logger);
app.Run();