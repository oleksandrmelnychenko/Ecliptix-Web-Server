using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Device;
using Google.Protobuf;
using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.AppDevices.Persistors;

public class AppDevicePersistorActor : PersistorBase<AppDeviceFailure>
{
    public AppDevicePersistorActor(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
        : base(dbContextFactory)
    {
        Become(Ready);
    }

    private void Ready()
    {
        Receive<RegisterAppDeviceIfNotExistActorEvent>(args =>
            ExecuteWithContext(
                    ctx => RegisterAppDeviceAsync(ctx, args.AppDevice),
                    "RegisterAppDevice")
                .PipeTo(Sender));
    }

    private static async Task<Result<AppDeviceRegisteredStateReply, AppDeviceFailure>> RegisterAppDeviceAsync(
        EcliptixSchemaContext ctx, AppDevice appDevice)
    {
        try
        {
            Guid appInstanceId = Helpers.FromByteStringToGuid(appDevice.AppInstanceId);
            Guid deviceId = Helpers.FromByteStringToGuid(appDevice.DeviceId);
            int deviceType = (int)appDevice.DeviceType;

            if (appInstanceId == Guid.Empty || deviceId == Guid.Empty)
            {
                return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Ok(new AppDeviceRegisteredStateReply
                {
                    Status = AppDeviceRegisteredStateReply.Types.Status.FailureInvalidRequest,
                    UniqueId = ByteString.Empty,
                    ServerPublicKey = ByteString.Empty
                });
            }

            DeviceEntity? existingDevice = await DeviceQueries.GetByDeviceId(ctx, deviceId);

            if (existingDevice != null)
            {
                return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Ok(new AppDeviceRegisteredStateReply
                {
                    Status = AppDeviceRegisteredStateReply.Types.Status.SuccessAlreadyExists,
                    UniqueId = Helpers.GuidToByteString(existingDevice.UniqueId),
                    ServerPublicKey = ByteString.Empty
                });
            }

            DeviceEntity newDevice = new()
            {
                AppInstanceId = appInstanceId,
                DeviceId = deviceId,
                DeviceType = deviceType
            };

            ctx.Devices.Add(newDevice);
            await ctx.SaveChangesAsync();

            return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Ok(new AppDeviceRegisteredStateReply
            {
                Status = AppDeviceRegisteredStateReply.Types.Status.SuccessNewRegistration,
                UniqueId = Helpers.GuidToByteString(newDevice.UniqueId),
                ServerPublicKey = ByteString.Empty
            });
        }
        catch (Exception ex)
        {
            return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Err(
                AppDeviceFailure.InfrastructureFailure($"Device registration failed: {ex.Message}"));
        }
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

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        return Props.Create(() => new AppDevicePersistorActor(dbContextFactory));
    }
}