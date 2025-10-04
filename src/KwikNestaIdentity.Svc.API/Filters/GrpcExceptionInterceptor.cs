using Grpc.Core.Interceptors;
using Grpc.Core;
using API.Common.Response.Model.Exceptions;

namespace KwikNestaIdentity.Svc.API.Filters
{
    public class GrpcExceptionInterceptor : Interceptor
    {
        private readonly ILogger<GrpcExceptionInterceptor> _logger;

        public GrpcExceptionInterceptor(ILogger<GrpcExceptionInterceptor> logger)
        {
            _logger = logger;
        }

        public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
            TRequest request,
            ServerCallContext context,
            UnaryServerMethod<TRequest, TResponse> continuation)
        {
            try
            {
                return await continuation(request, context);
            }
            catch(RpcException)
            {
                throw;
            }
            catch (ArgumentException ex)
            {
                _logger.LogError(ex, ex.Message);
                throw new RpcException(new Status(StatusCode.InvalidArgument, ex.Message));
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogError(ex, ex.Message);
                throw new RpcException(new Status(StatusCode.PermissionDenied, ex.Message));
            }
            catch(NullReferenceException ex)
            {
                _logger.LogError(ex, ex.Message);
                throw new RpcException(new Status(StatusCode.Internal, ex.Message));
            }
            catch(BadRequestException ex)
            {
                _logger.LogError(ex, ex.Message);
                throw new RpcException(new Status(StatusCode.InvalidArgument, ex.Message));
            }
            catch(NotFoundException ex)
            {
                _logger.LogError(ex, ex.Message);
                throw new RpcException(new Status(StatusCode.NotFound, ex.Message));
            }
            catch (ForbiddenException ex)
            {
                _logger.LogError(ex, ex.Message);
                throw new RpcException(new Status(StatusCode.PermissionDenied, ex.Message));
            }
            catch(UnauthorizedException ex)
            {
                _logger.LogError(ex, ex.Message);
                throw new RpcException(new Status(StatusCode.PermissionDenied, ex.Message));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception in gRPC service");
                throw new RpcException(new Status(StatusCode.Internal, "Internal server error"));
            }
        }
    }
}
