using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.Persistors;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Ecliptix.Domain.AppDevices.Persistors;

public abstract class AppDevicePersistorBase(
    IDbDataSource npgsqlDataSource,
    ILogger logger
) : PersistorBase<AppDeviceFailure>(npgsqlDataSource, logger)
{
    protected override AppDeviceFailure MapNpgsqlException(NpgsqlException ex)
    {
        return ex.SqlState switch
        {
            PostgreSqlErrorCodes.ConnectionException or
                PostgreSqlErrorCodes.ConnectionDoesNotExist or
                PostgreSqlErrorCodes.ConnectionFailure
                => AppDeviceFailure.PersistorAccess(AppDeviceMessageKeys.DataAccess, ex),

            PostgreSqlErrorCodes.SerializationFailure or
                PostgreSqlErrorCodes.UniqueViolation
                => AppDeviceFailure.PersistorAccess(AppDeviceMessageKeys.DataAccess, ex),

            PostgreSqlErrorCodes.ForeignKeyViolation
                => AppDeviceFailure.PersistorAccess(AppDeviceMessageKeys.DataAccess, ex),

            PostgreSqlErrorCodes.CheckViolation or
                PostgreSqlErrorCodes.InvalidTextRepresentation
                => AppDeviceFailure.Validation(),

            _ => AppDeviceFailure.PersistorAccess(AppDeviceMessageKeys.DataAccess, ex)
        };
    }

    protected override AppDeviceFailure CreateTimeoutFailure(TimeoutException ex) =>
        AppDeviceFailure.PersistorAccess(AppDeviceMessageKeys.DataAccess, ex);

    protected override AppDeviceFailure CreateGenericFailure(Exception ex) =>
        AppDeviceFailure.Generic(AppDeviceMessageKeys.Generic, ex);
}