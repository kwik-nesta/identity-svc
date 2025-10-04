using Grpc.Core;
using KwikNesta.Contracts.Enums;
using KwikNestaIdentity.Svc.Application.Commands.UpdateBasicDetails;
using KwikNestaIdentity.Svc.Application.DTOs;
using KwikNestaIdentity.Svc.Application.Extensions;
using KwikNestaIdentity.Svc.Application.Queries.LoggedInUser;
using KwikNestaIdentity.Svc.Application.Queries.Users;
using KwikNestaIdentity.Svc.Contract.Protos;
using MediatR;

namespace KwikNestaIdentity.Svc.API.GrpcServices
{
    public class GrpcUserService : AppUserService.AppUserServiceBase
    {
        private readonly IMediator _mediator;

        public GrpcUserService(IMediator mediator)
        {
            _mediator = mediator;
        }

        /// <summary>
        /// Get loggedin user details
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<GetLoggedInUserResponse> GetLoggedInUser(Empty request, ServerCallContext context)
        {
            var response = await _mediator.Send(new CurrentUserQuery());

            return new GetLoggedInUserResponse
            {
                User = MapData(response)
            };
        }

        /// <summary>
        /// Update user basic details
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<UpdateBasicUserDetailsResponse> UpdateBasicUserDetails(UpdateBasicUserDetailsRequest request, ServerCallContext context)
        {
            var response = await _mediator.Send(new UpdateBasicUserDetailsCommand
            {
                FirstName = request.FirstName,
                LastName = request.LastName,
                OtherName = request.OtherName,
                Gender = EnumMapper.Map<GrpcUserGender, Gender>(request.Gender)
            });

            return new UpdateBasicUserDetailsResponse
            {
                Response = new UserStringResponse
                {
                    Message = response.Message,
                    Status = response.Status
                }
            };
        }

        /// <summary>
        /// Get user by id
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<GetUserByIdResponse> GetUserById(GetUserByIdRequest request, ServerCallContext context)
        {
            var response = await _mediator.Send(new GetUserQuery(request.UserId));

            return new GetUserByIdResponse
            {
                User = MapData(response)
            };
        }

        /// <summary>
        /// Get users by their ids
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<GetUsersByIdsResponse> GetUsersByIds(GetUsersByIdsRequest request, ServerCallContext context)
        {
            var response = await _mediator.Send(new GetUsersQuery(request.UserIds.ToList()));

            return new GetUsersByIdsResponse
            {
                Users = { response.Select(MapData) }
            };
        }

        /// <summary>
        ///Get paged list of users
        /// </summary>
        /// <param name="request">The request received from the client.</param>
        /// <param name="context">The context of the server-side call handler being invoked.</param>
        /// <returns>The response to send back to the client (wrapped by a task).</returns>
        public override async Task<GetPagedUsersResponse> GetPagedUsers(GetPagedUsersRequest request, ServerCallContext context)
        {
            var response = await _mediator.Send(new GetPagedUsersQuery
            {
                Page = request.Page,
                PageSize = request.Size,
                Search = request.Search,
                Gender = EnumMapper.Map<GrpcUserGender, Gender>(request.Gender),
                Status = EnumMapper.Map<GrpcUserStatus, UserStatus>(request.Status)
            });

            return new GetPagedUsersResponse
            {
                MetaData = new UserPageMetaData
                {
                    Page = response.Meta.Page,
                    Size = response.Meta.Size,
                    TotalCount = response.Meta.TotalCount,
                    HasNext = response.Meta.HasNext,
                    HasPrevious = response.Meta.HasPrevious
                },
                Users = { response.Users.Select(MapData) }
            };
        }

        public static User MapData(CurrentUserDto user)
        {
            return new User
            {
                Id = user.Id,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                MiddleName = user.MiddleName ?? string.Empty,
                PhoneNumber = user.PhoneNumber,
                StatusDescription = user.Status
            };
        }
    }
}