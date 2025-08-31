using CSharpTypes.Extensions.Enumeration;
using Grpc.Core;
using KwikNestaIdentity.Svc.Contract.Protos;
using KwikNestaIdentity.Svc.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace KwikNestaIdentity.Svc.API.ProtoImpl
{
    public class IdentityGrpcService : IdentityService.IdentityServiceBase
    {
        private readonly UserManager<AppUser> _userManager;

        public IdentityGrpcService(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

        public override async Task<GetUserByIdResponse> GetUserById(GetUserByIdRequest request,
                                                                    ServerCallContext context)
        {
            var user = await _userManager.FindByIdAsync(request.UserId) ?? 
                throw new RpcException(new Status(StatusCode.NotFound, $"User {request.UserId} not found"));

            return new GetUserByIdResponse
            {
                User = new User
                {
                    Id = user.Id,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Email = user.Email,
                    Username = user.UserName,
                    Status = user.Status.GetDescription()
                }
            };
        }

        public override async Task<BatchGetUsersResponse> BatchGetUsers(BatchGetUsersRequest request,
                                                                        ServerCallContext context)
        {
            var response = new BatchGetUsersResponse();
            var users = await _userManager.Users.
                Where(u => request.UserIds.Contains(u.Id))
                .ToListAsync();

            response.Users.AddRange(users.Select(u => new User
            {
                Id = u.Id,
                FirstName = u.FirstName,
                LastName = u.LastName,
                Email = u.Email,
                Username = u.UserName,
                Status = u.Status.GetDescription()
            }));
            return response;
        }
    }
}