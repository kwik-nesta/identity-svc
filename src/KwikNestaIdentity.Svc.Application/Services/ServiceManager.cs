using CrossQueue.Hub.Services.Interfaces;
using EFCore.CrudKit.Library.Data.Interfaces;
using KwikNestaIdentity.Svc.Application.Services.Interfaces;
using KwikNestaIdentity.Svc.Domain.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace KwikNestaIdentity.Svc.Application.Services
{
    public class ServiceManager : IServiceManager
    {
        private readonly Lazy<ITokenService> _tokenService;
        private readonly Lazy<IUserService> _userService;
        private readonly Lazy<IAuthService> _authService;

        public ServiceManager(IEFCoreCrudKit crudKit, IOptions<Jwt> options, UserManager<AppUser> userManager,
            SignInManager<AppUser> signInManager, IHttpContextAccessor contextAccessor, IEFCoreCrudKit eFCoreCrud,
            IRabbitMQPubSub pubSub)
        {
            _tokenService = new Lazy<ITokenService>(() =>
                new TokenService(crudKit, options, userManager));
            _userService = new Lazy<IUserService>(() =>
                new UserService(userManager, contextAccessor, pubSub));
            _authService = new Lazy<IAuthService>(() => 
                new AuthService(userManager, signInManager, contextAccessor, crudKit, pubSub));
        }

        public ITokenService Token => _tokenService.Value;
        public IUserService User => _userService.Value;
        public IAuthService Auth => _authService.Value;
    }
}