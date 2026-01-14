using System.Data.Common;
using Akka.Actor;
using Ecliptix.DeviceProvisioning.Domain.Events;
using Ecliptix.DeviceProvisioning.Domain.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors;
using Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.Protobuf.Device;
using Ecliptix.SharedKernel;
using Google.Protobuf;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Ecliptix.DeviceProvisioning.Infrastructure.Persistors;

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
                    (schemaContext, cancellationToken) => RegisterAppDeviceAsync(schemaContext, args.AppDevice, cancellationToken),
                    "RegisterAppDevice",
                    args.CancellationToken)
                .PipeTo(Sender));
    }

    private static async Task<Result<DeviceRegistrationResponse, AppDeviceFailure>> RegisterAppDeviceAsync(
        EcliptixSchemaContext schemaContext, Device appDevice, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await schemaContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            Guid appInstanceId = Helpers.FromByteStringToGuid(appDevice.ApplicationInstanceId);
            Guid deviceId = Helpers.FromByteStringToGuid(appDevice.DeviceId);

            int deviceType = (int)appDevice.DeviceType;

            if (appInstanceId == Guid.Empty || deviceId == Guid.Empty)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<DeviceRegistrationResponse, AppDeviceFailure>.Ok(new DeviceRegistrationResponse
                {
                    Result = DeviceRegistrationResponse.Types.Result.DeviceRegistrationResultInvalidRequest
                });
            }

            Option<DeviceEntity> existingDeviceOpt = await DeviceQueries.GetByAppInstanceId(schemaContext, appInstanceId, cancellationToken);

            if (existingDeviceOpt.IsSome)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<DeviceRegistrationResponse, AppDeviceFailure>.Ok(new DeviceRegistrationResponse
                {
                    Result = DeviceRegistrationResponse.Types.Result.DeviceRegistrationResultAlreadyExists
                });
            }

            DeviceEntity newDevice = new()
            {
                AppInstanceId = appInstanceId,
                DeviceId = deviceId,
                DeviceType = deviceType
            };

            schemaContext.Devices.Add(newDevice);

            await schemaContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return Result<DeviceRegistrationResponse, AppDeviceFailure>.Ok(new DeviceRegistrationResponse
            {
                Result = DeviceRegistrationResponse.Types.Result.DeviceRegistrationResultNewRegistration
            });
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            return Result<DeviceRegistrationResponse, AppDeviceFailure>.Err(
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
