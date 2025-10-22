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
                    (ctx, cancellationToken) => RegisterAppDeviceAsync(ctx, args.AppDevice, cancellationToken),
                    "RegisterAppDevice",
                    args.CancellationToken)
                .PipeTo(Sender));
    }

    private static async Task<Result<AppDeviceRegisteredStateReply, AppDeviceFailure>> RegisterAppDeviceAsync(
        EcliptixSchemaContext ctx, AppDevice appDevice, CancellationToken cancellationToken)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            Guid appInstanceId = Helpers.FromByteStringToGuid(appDevice.AppInstanceId);
            Guid deviceId = Helpers.FromByteStringToGuid(appDevice.DeviceId);
            int deviceType = (int)appDevice.DeviceType;

            if (appInstanceId == Guid.Empty || deviceId == Guid.Empty)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Ok(new AppDeviceRegisteredStateReply
                {
                    Status = AppDeviceRegisteredStateReply.Types.Status.FailureInvalidRequest,
                    UniqueId = ByteString.Empty,
                    ServerPublicKey = ByteString.Empty
                });
            }

            Option<DeviceEntity> existingDeviceOpt = await DeviceQueries.GetByAppInstanceId(ctx, appInstanceId, cancellationToken);

            if (existingDeviceOpt.HasValue)
            {
                DeviceEntity existingDevice = existingDeviceOpt.Value!;
                await transaction.RollbackAsync(CancellationToken.None);
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
                DeviceType = deviceType
            };

            ctx.Devices.Add(newDevice);
            await ctx.SaveChangesAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);
            return Result<AppDeviceRegisteredStateReply, AppDeviceFailure>.Ok(new AppDeviceRegisteredStateReply
            {
                Status = AppDeviceRegisteredStateReply.Types.Status.SuccessNewRegistration,
                UniqueId = Helpers.GuidToByteString(newDevice.UniqueId),
                ServerPublicKey = ByteString.Empty
            });
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(CancellationToken.None);
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
