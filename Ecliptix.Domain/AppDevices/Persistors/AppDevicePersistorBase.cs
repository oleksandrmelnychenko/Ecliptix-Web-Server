using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.Persistors;
using Microsoft.Extensions.Logging;

namespace Ecliptix.Domain.AppDevices.Persistors;

public abstract class AppDevicePersistorBase(
    IDbConnectionFactory npgsqlDataSource,
    ILogger logger
) : PersistorBase<AppDeviceFailure>(npgsqlDataSource, logger)
{
    protected override AppDeviceFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return AppDeviceFailure.PersistorAccess(AppDeviceMessageKeys.DataAccess, ex);
    }

    protected override AppDeviceFailure CreateGenericFailure(Exception ex)
    {
        return AppDeviceFailure.Generic(AppDeviceMessageKeys.Generic, ex);
    }
}