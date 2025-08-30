using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace KwikNestaIdentity.Svc.API.Filters
{
    public class RequireAudienceHeaderAttribute : Attribute, IAsyncActionFilter
    {
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            if (!context.HttpContext.Request.Headers.TryGetValue("Audience", out var aud))
            {
                context.Result = new UnauthorizedObjectResult(new { Message = "Missing or invalid Audience header" });
                return;
            }

            await next();
        }
    }
}