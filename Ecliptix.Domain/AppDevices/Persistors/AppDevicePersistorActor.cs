using System.Data;
using System.Data.Common;
using Akka.Actor;
using Dapper;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Device;
using Google.Protobuf;
using Serilog;

namespace Ecliptix.Domain.AppDevices.Persistors;

public class AppDeviceRegisterResult
{
    public Guid UniqueId { get; set; }
    public int Status { get; set; }
}

public class AppDevicePersistorActor : PersistorBase<AppDeviceFailure>
{
    private const string RegisterAppDeviceSp = "dbo.SP_RegisterAppDevice";

    public AppDevicePersistorActor(IDbConnectionFactory connectionFactory)
        : base(connectionFactory)
    {
        Become(Ready);
    }

    private void Ready()
    {
        Receive<RegisterAppDeviceIfNotExistActorEvent>(args =>
            ExecuteWithConnection(
                    conn => RegisterAppDeviceAsync(conn, args.AppDevice),
                    "RegisterAppDevice",
                    RegisterAppDeviceSp)
                .PipeTo(Sender));
    }

    private static async Task<Result<AppDeviceRegisteredStateReply, AppDeviceFailure>> RegisterAppDeviceAsync(
        IDbConnection connection, AppDevice appDevice)
    {
        DynamicParameters parameters = new();
        parameters.Add("@AppInstanceId", Helpers.FromByteStringToGuid(appDevice.AppInstanceId));
        parameters.Add("@DeviceId", Helpers.FromByteStringToGuid(appDevice.DeviceId));
        parameters.Add("@DeviceType", (int)appDevice.DeviceType);

        AppDeviceRegisterResult? result = await connection.QuerySingleOrDefaultAsync<AppDeviceRegisterResult>(
            RegisterAppDeviceSp,
            parameters,
            commandType: CommandType.StoredProcedure);

        if (result == null)
        {
            return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Err(
                AppDeviceFailure.InfrastructureFailure("Database operation returned no result"));
        }

        AppDeviceRegisteredStateReply.Types.Status currentStatus = result.Status switch
        {
            1 => AppDeviceRegisteredStateReply.Types.Status.SuccessAlreadyExists,
            2 => AppDeviceRegisteredStateReply.Types.Status.SuccessNewRegistration,
            0 => AppDeviceRegisteredStateReply.Types.Status.FailureInvalidRequest,
            _ => LogAndReturnInternalError(result.Status)
        };

        static AppDeviceRegisteredStateReply.Types.Status LogAndReturnInternalError(int status)
        {
            return AppDeviceRegisteredStateReply.Types.Status.FailureInternalError;
        }

        return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Ok(new AppDeviceRegisteredStateReply
        {
            Status = currentStatus,
            UniqueId = Helpers.GuidToByteString(result.UniqueId),
            ServerPublicKey = ByteString.Empty
        });
    }

    protected override AppDeviceFailure MapDbException(DbException ex)
    {
        return AppDeviceFailure.InfrastructureFailure("Database operation failed", ex);
    }

    protected override AppDeviceFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return AppDeviceFailure.InfrastructureFailure(AppDeviceMessageKeys.DataAccess, ex);
    }

    protected override AppDeviceFailure CreateGenericFailure(Exception ex)
    {
        return AppDeviceFailure.InternalError("Unexpected error occurred", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }

    public static Props Build(IDbConnectionFactory connectionFactory)
    {
        return Props.Create(() => new AppDevicePersistorActor(connectionFactory));
    }
}