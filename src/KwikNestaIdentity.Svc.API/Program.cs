using CrossQueue.Hub.Shared.Extensions;
using DiagnosKit.Core.Configurations;
using DiagnosKit.Core.Extensions;
using DiagnosKit.Core.Logging;
using KwikNestaIdentity.Svc.API.Extensions;
using KwikNestaIdentity.Svc.API.ProtoImpl;
using KwikNestaIdentity.Svc.Infrastructure;
using Microsoft.EntityFrameworkCore;

SerilogBootstrapper.UseBootstrapLogger();
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services
    .ConfigureIdentityAndDbContext(builder.Configuration)
    .ConfigureCors()
    .ConfigureServices()
    .ConfigureSwaggerDocs()
    .ConfigureApiVersioning()
    .AddCrossQueueHubRabbitMqBus(builder.Configuration)
    .ConfigureJwt(builder.Configuration)
    .AddDiagnosKitObservability(serviceName: builder.Environment.ApplicationName, serviceVersion: "1.0.0")
    .AddLoggerManager();

builder.Host.ConfigureSerilogESSink();
builder.Services.AddAuthorization();
builder.Services.AddGrpc();

var app = builder.Build();

var logger = app.Services.GetRequiredService<ILogger<Program>>();
app.UseDiagnosKitPrometheus()
    .UseDiagnosKitErrorHandler()
    .UseDiagnosKitLogEnricher();

// Map gRPC service
app.MapGrpcService<IdentityGrpcService>();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
if (app.Environment.IsDevelopment())
{
    // Run migrations at startup (optional)
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Database.Migrate();
    }
}

await app.SeedInitialData(logger);
app.UseCors("CorsPolicy");
app.Run();