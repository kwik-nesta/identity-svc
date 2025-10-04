using CrossQueue.Hub.Shared.Extensions;
using DiagnosKit.Core.Configurations;
using DiagnosKit.Core.Extensions;
using DiagnosKit.Core.Logging;
using DiagnosKit.Core.Logging.Contracts;
using KwikNestaIdentity.Svc.API.Extensions;
using KwikNestaIdentity.Svc.API.Filters;
using KwikNestaIdentity.Svc.API.GrpcServices;
using KwikNestaIdentity.Svc.API.Middlewares;
using KwikNestaIdentity.Svc.Application.Commands.Login;
using System.Net;

SerilogBootstrapper.UseBootstrapLogger();
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services
    .ConfigureIdentityAndDbContext(builder.Configuration)
    .AddCrossQueueHubRabbitMqBus(builder.Configuration)
    .ConfigureJwt(builder.Configuration)
    .AddDiagnosKitObservability(serviceName: builder.Environment.ApplicationName, serviceVersion: "1.0.0")
    .ConfigureSwaggerDocs()
    .ConfigureApiVersioning()
    .AddLoggerManager();

builder.Services.AddMediatR(cfg =>
    cfg.RegisterServicesFromAssembly(typeof(LoginCommand).Assembly));

builder.Host.ConfigureSerilogESSink();
builder.Services.AddAuthorization();
builder.Services.AddGrpc(options =>
{
    options.Interceptors.Add<GrpcExceptionInterceptor>();
});

var app = builder.Build();

var logger = app.Services.GetRequiredService<ILoggerManager>();
app.UseGlobalExceptionHandler(logger);
app.UseDiagnosKitPrometheus();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();

app.UseRouting();
app.UseAuthorization();

app.MapControllers();

app.UseGrpcWeb(new GrpcWebOptions { DefaultEnabled = true });
app.MapGrpcService<GrpcUserService>().EnableGrpcWeb();
app.MapGrpcService<GrpcAuthService>().EnableGrpcWeb();
app.MapGet("/", () => new
{
    Status = HttpStatusCode.OK,
    Message = "Kwik Nesta Identity Service is running..."
});

app.RunMigrations(true);
await app.SeedInitialData(logger);
app.Run();