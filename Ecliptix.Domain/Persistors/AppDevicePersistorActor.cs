using Akka.Actor;
using Ecliptix.Protobuf.AppDevice;
using Npgsql;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Domain.Persistors;

public record RegisterAppDeviceIfNotExistCommand(AppDevice AppDevice);

public class AppDevicePersistorActor : ReceiveActor
{
    private const string SqlRegisterAppDevice = @"
        SELECT (r).unique_id, (r).status
        FROM register_app_device_if_not_exists(
            @app_instance_id,
            @device_id,
            @device_type
        ) AS r;
    ";

    private const string ParamAppInstanceId = "app_instance_id";
    private const string ParamDeviceId = "device_id";
    private const string ParamDeviceType = "device_type";

    private readonly NpgsqlDataSource _npgsqlDataSource;

    public AppDevicePersistorActor(NpgsqlDataSource npgsqlDataSource)
    {
        _npgsqlDataSource = npgsqlDataSource;

        Become(Ready);
    }

    public static Props Build(NpgsqlDataSource npgsqlDataSource) =>
        Props.Create(() => new AppDevicePersistorActor(npgsqlDataSource));

    private void Ready()
    {
        ReceiveAsync<RegisterAppDeviceIfNotExistCommand>(HandleRegisterAppDeviceIfNotExistCommand);
    }

    private async Task HandleRegisterAppDeviceIfNotExistCommand(RegisterAppDeviceIfNotExistCommand command)
    {
        Result<(Guid, int), ShieldFailure> operationResult = await RegisterAppDevice(command.AppDevice);
        Sender.Tell(operationResult);
    }

    private async Task<Result<(Guid, int), ShieldFailure>> RegisterAppDevice(
        AppDevice appDevice)
    {
        await using NpgsqlConnection connection = await _npgsqlDataSource.OpenConnectionAsync();
        await using NpgsqlCommand cmd = new(SqlRegisterAppDevice, connection);

        cmd.Parameters.AddWithValue(ParamAppInstanceId, appDevice.AppInstanceId);
        cmd.Parameters.AddWithValue(ParamDeviceId, appDevice.DeviceId);
        cmd.Parameters.AddWithValue(ParamDeviceType, appDevice.DeviceType);

        await using NpgsqlDataReader reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return Result<(Guid, int), ShieldFailure>.Err(ShieldFailure.DataAccess("Failed to register app device."));
        }

        Guid uniqueId = reader.GetFieldValue<Guid>(0);
        int status = reader.GetInt32(1);

        return Result<(Guid, int), ShieldFailure>.Ok((uniqueId, status));
    }
}