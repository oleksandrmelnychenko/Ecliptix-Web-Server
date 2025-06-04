using Akka.Actor;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.AppDevices.Persistors.Utilities;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.AppDevice;
using Microsoft.Extensions.Logging;
using Npgsql;
using NpgsqlTypes;

namespace Ecliptix.Domain.AppDevices.Persistors;

public class AppDevicePersistorActor : AppDevicePersistorBase
{
    public AppDevicePersistorActor(NpgsqlDataSource npgsqlDataSource, ILogger<AppDevicePersistorActor> logger)
        : base(npgsqlDataSource, logger)
    {
        Become(Ready);
    }

    public static Props Build(NpgsqlDataSource npgsqlDataSource, ILogger<AppDevicePersistorActor> logger) =>
        Props.Create(() => new AppDevicePersistorActor(npgsqlDataSource, logger));

    private void Ready()
    {
        ReceiveAsync<RegisterAppDeviceIfNotExistActorEvent>(HandleRegisterAppDeviceIfNotExistCommand);
    }

    private async Task HandleRegisterAppDeviceIfNotExistCommand(RegisterAppDeviceIfNotExistActorEvent actorEvent)
    {
        await RegisterAppDevice(actorEvent.AppDevice);
    }

    private async Task RegisterAppDevice(AppDevice appDevice) =>
        await ExecuteWithConnection(async npgsqlConnection =>
        {
            await using NpgsqlCommand cmd = CreateCommand(npgsqlConnection, Queries.RegisterAppDevice,
                new NpgsqlParameter(Parameters.AppInstanceId, NpgsqlDbType.Uuid)
                {
                    Value = Helpers.FromByteStringToGuid(appDevice.AppInstanceId)
                },
                new NpgsqlParameter(Parameters.DeviceId, NpgsqlDbType.Uuid)
                {
                    Value = Helpers.FromByteStringToGuid(appDevice.DeviceId)
                },
                new NpgsqlParameter(Parameters.DeviceType, NpgsqlDbType.Integer)
                {
                    Value = (int)appDevice.DeviceType
                }
            );

            await using NpgsqlDataReader reader = await cmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync())
            {
                return Result<(Guid, int), AppDeviceFailure>.Err(
                    AppDeviceFailure.PersistorAccess(AppDeviceMessageKeys.RegistrationNoResult));
            }

            Guid uniqueId = reader.GetFieldValue<Guid>(0);
            int status = reader.GetInt32(1);

            return Result<(Guid, int), AppDeviceFailure>.Ok((uniqueId, status));
        }, OperationNames.RegisterAppDevice);
}