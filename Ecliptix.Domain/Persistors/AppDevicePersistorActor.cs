using Akka.Actor;
using Ecliptix.Protobuf.AppDevice;
using Npgsql;
using Ecliptix.Domain.Utilities;
using NpgsqlTypes;

namespace Ecliptix.Domain.Persistors;

public record RegisterAppDeviceIfNotExistCommand(AppDevice AppDevice);

public class AppDevicePersistorActor : ReceiveActor
{
    private const string SqlRegisterAppDevice = @"
        SELECT (r).unique_id, (r).status
        FROM public.register_app_device_if_not_exists(
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
        await RegisterAppDevice(command.AppDevice);
    }

    private async Task RegisterAppDevice(AppDevice appDevice)
    {
        int deviceTypeInt = (int)appDevice.DeviceType;

        try
        {
            await using NpgsqlConnection connection = await _npgsqlDataSource.OpenConnectionAsync();
            await using NpgsqlCommand cmd = new(SqlRegisterAppDevice, connection);

            cmd.Parameters.Add(ParamAppInstanceId, NpgsqlDbType.Uuid).Value =
                Helpers.FromByteStringToGuid(appDevice.AppInstanceId);
            cmd.Parameters.Add(ParamDeviceId, NpgsqlDbType.Uuid).Value =
                Helpers.FromByteStringToGuid(appDevice.DeviceId);
            cmd.Parameters.Add(ParamDeviceType, NpgsqlDbType.Integer).Value = deviceTypeInt;

            await using NpgsqlDataReader reader = await cmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync())
            {
                Sender.Tell(Result<(Guid, int), ShieldFailure>.Err(
                    ShieldFailure.DataAccess("Failed to register app device (no result returned).")));
            }

            Guid uniqueId = reader.GetFieldValue<Guid>(0);
            int status = reader.GetInt32(1);

            Sender.Tell(Result<(Guid, int), ShieldFailure>.Ok((uniqueId, status)));
        }
        catch (NpgsqlException dbEx)
        {
            Sender.Tell(Result<(Guid, int), ShieldFailure>.Err(
                ShieldFailure.DataAccess($"Database error during registration: {dbEx.Message}", dbEx)));
        }
        catch (Exception ex)
        {
            Sender.Tell(Result<(Guid, int), ShieldFailure>.Err(
                ShieldFailure.Generic($"Unexpected error during registration: {ex.Message}", ex)));
        }
    }
}