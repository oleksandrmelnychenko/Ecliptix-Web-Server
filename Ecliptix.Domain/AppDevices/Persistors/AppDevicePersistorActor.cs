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
using Ecliptix.Protobuf.Device;
using Google.Protobuf;

namespace Ecliptix.Domain.AppDevices.Persistors;

public class AppDeviceRegisterResult
{
    public Guid UniqueId { get; set; }
    public int Status { get; set; }
}

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

        AppDeviceRegisterResult? result = await connection.QuerySingleOrDefaultAsync<AppDeviceRegisterResult>(
            "dbo.RegisterAppDeviceIfNotExists",
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result == null)
        {
            return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Err(
                AppDeviceFailure.InfrastructureFailure());
        }

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

    /// <summary>
    /// AOT-compatible Props builder - parameters captured but no closures
    /// </summary>
    public static Props Build(IDbConnectionFactory connectionFactory, IOpaqueProtocolService opaqueProtocolService)
    {
        return Props.Create(() => new AppDevicePersistorActor(connectionFactory, opaqueProtocolService));
    }
}
