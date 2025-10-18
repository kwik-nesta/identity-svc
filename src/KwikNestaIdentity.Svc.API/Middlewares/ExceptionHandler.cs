using API.Common.Response.Model.Exceptions;
using DiagnosKit.Core.Logging.Contracts;
using KwikNesta.Contracts.Models;
using Microsoft.AspNetCore.Diagnostics;
using System.Net;
using System.Text.Json;

namespace KwikNestaIdentity.Svc.API.Middlewares
{
    public static class ExceptionHandler
    {
        public static void UseGlobalExceptionHandler(this WebApplication app,
                                                     ILoggerManager logger)
        {
           app.UseExceptionHandler(builder =>
                {
                    builder.Run(async context =>
                    {
                        context.Response.ContentType = "application/json";
                        var contextFeature = context.Features.Get<IExceptionHandlerFeature>();

                        if (contextFeature != null)
                        {
                            logger.LogError(contextFeature.Error, "An error occurred");
                            var message = contextFeature.Error.Message;
                            switch (contextFeature.Error)
                            {
                                case BadRequestException:
                                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                                    message = contextFeature.Error.Message;
                                    break;
                                case NotFoundException:
                                    context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                                    message = contextFeature.Error.Message;
                                    break;
                                case ForbiddenException:
                                    context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                                    message = contextFeature.Error.Message;
                                    break;
                                default:
                                    context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                                    break;
                            }

                            await context.Response.WriteAsync(JsonSerializer.Serialize(new ApiResult<string>(message, context.Response.StatusCode)));
                        }
                    });
                });
        }
    }
}