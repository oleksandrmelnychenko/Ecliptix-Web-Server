using System.Data;
using System.Data.Common;
using System.Text;
using Akka.Actor;
using Dapper;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.OPAQUE;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.AppDevice;
using Google.Protobuf;
using Microsoft.Extensions.Logging;

namespace Ecliptix.Domain.AppDevices.Persistors;

public class AppDevicePersistorActor : PersistorBase<AppDeviceFailure>
{
    private readonly IOpaqueProtocolService _opaqueProtocolService;

    private const string RegisterAppDeviceSp = "dbo.RegisterAppDeviceIfNotExists";

    public AppDevicePersistorActor(IDbConnectionFactory connectionFactory, IOpaqueProtocolService opaqueProtocolService)
        : base(connectionFactory)
    {
        _opaqueProtocolService = opaqueProtocolService;
        Become(Ready);
    }

    private void Ready()
    {
        Receive<RegisterAppDeviceIfNotExistActorEvent>(args =>
            ExecuteWithConnection(
                    conn => RegisterAppDeviceAsync(conn, args.AppDevice, _opaqueProtocolService.GetPublicKey()),
                    "RegisterAppDevice",
                    RegisterAppDeviceSp)
                .PipeTo(Sender));
    }

    private static async Task<Result<AppDeviceRegisteredStateReply, AppDeviceFailure>> RegisterAppDeviceAsync(
        IDbConnection connection, AppDevice appDevice, byte[] opaqueProtocolPublicKey)
    {
        var parameters = new
        {
            AppInstanceId = Helpers.FromByteStringToGuid(appDevice.AppInstanceId),
            DeviceId = Helpers.FromByteStringToGuid(appDevice.DeviceId),
            DeviceType = (int)appDevice.DeviceType
        };

        (Guid UniqueId, int Status) result = await connection.QuerySingleOrDefaultAsync<(Guid UniqueId, int Status)>(
            RegisterAppDeviceSp,
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result.Equals(default))
            return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Err(
                AppDeviceFailure.InfrastructureFailure());

        AppDeviceRegisteredStateReply.Types.Status currentStatus = result.Status switch
        {
            1 => AppDeviceRegisteredStateReply.Types.Status.SuccessAlreadyExists,
            2 => AppDeviceRegisteredStateReply.Types.Status.SuccessNewRegistration,
            0 => AppDeviceRegisteredStateReply.Types.Status.FailureInvalidRequest,
            _ => AppDeviceRegisteredStateReply.Types.Status.FailureInternalError
        };

        return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Ok(new AppDeviceRegisteredStateReply
        {
            Status = currentStatus,
            UniqueId = Helpers.GuidToByteString(result.UniqueId),
            ServerPublicKey = ByteString.CopyFrom(opaqueProtocolPublicKey)
        });
    }

    protected override AppDeviceFailure MapDbException(DbException ex)
    {
        return AppDeviceFailure.InfrastructureFailure(ex: ex);
    }

    protected override AppDeviceFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return AppDeviceFailure.InfrastructureFailure(AppDeviceMessageKeys.DataAccess, ex);
    }

    protected override AppDeviceFailure CreateGenericFailure(Exception ex)
    {
        return AppDeviceFailure.InternalError(ex: ex);
    }

    public static Props Build(IDbConnectionFactory connectionFactory, IOpaqueProtocolService opaqueProtocolService)
    {
        return Props.Create(() => new AppDevicePersistorActor(connectionFactory, opaqueProtocolService));
    }
}