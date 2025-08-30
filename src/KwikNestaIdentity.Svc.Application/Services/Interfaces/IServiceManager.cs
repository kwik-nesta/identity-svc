namespace KwikNestaIdentity.Svc.Application.Services.Interfaces
{
    public interface IServiceManager
    {
        ITokenService Token { get; }
        IUserService User { get; }
        IAuthService Auth { get; }
    }
}
