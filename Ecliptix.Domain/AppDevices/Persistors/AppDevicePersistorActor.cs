using System.Data;
using System.Data.Common;
using Akka.Actor;
using Dapper;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.AppDevice;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace Ecliptix.Domain.AppDevices.Persistors;

public class AppDevicePersistorActor : AppDevicePersistorBase
{
    public AppDevicePersistorActor(IDbConnectionFactory connectionFactory, ILogger<AppDevicePersistorActor> logger)
        : base(connectionFactory, logger)
    {
        Become(Ready);
    }

    public static Props Build(IDbConnectionFactory connectionFactory, ILogger<AppDevicePersistorActor> logger) =>
        Props.Create(() => new AppDevicePersistorActor(connectionFactory, logger));

    private void Ready()
    {
        Receive<RegisterAppDeviceIfNotExistActorEvent>(args =>
            ExecuteWithConnection(conn => RegisterAppDeviceAsync(conn, args.AppDevice), "RegisterAppDevice")
                .PipeTo(Sender));
    }

    private async Task<Result<(Guid UniqueId, int Status), AppDeviceFailure>> RegisterAppDeviceAsync(
        IDbConnection connection, AppDevice appDevice)
    {
        using IDbCommand cmd = CreateCommand(connection, "dbo.RegisterAppDeviceIfNotExists",
            CommandType.StoredProcedure,
            CreateParameter("@AppInstanceId", Helpers.FromByteStringToGuid(appDevice.AppInstanceId)),
            CreateParameter("@DeviceId", Helpers.FromByteStringToGuid(appDevice.DeviceId)),
            CreateParameter("@DeviceType", (int)appDevice.DeviceType)
        );

        (Guid UniqueId, int Status) result = await (cmd as DbCommand)!.ExecuteReaderAsync()
            .ContinueWith(task =>
            {
                using DbDataReader reader = task.Result;
                return reader.Parse<(Guid UniqueId, int Status)>().SingleOrDefault();
            }, TaskScheduler.Default);

        if (result.UniqueId == Guid.Empty)
        {
            return Result<(Guid, int), AppDeviceFailure>.Err(
                AppDeviceFailure.PersistorAccess(AppDeviceMessageKeys.RegistrationNoResult));
        }

        return Result<(Guid, int), AppDeviceFailure>.Ok(result);
    }

    protected override IDbDataParameter CreateParameter(string name, object value)
    {
        return new SqlParameter(name, value);
    }

    protected override AppDeviceFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return AppDeviceFailure.PersistorAccess(
                $"SQL Error {sqlEx.Number}: {sqlEx.Message}",
                sqlEx
            );
        }

        return AppDeviceFailure.PersistorAccess(
            $"Database Error: {ex.Message}",
            ex
        );
    }
}