using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Persistors;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Ecliptix.Domain.Memberships.Persistors;

public abstract class VerificationFlowPersistorBase(
    IDbDataSource npgsqlDataSource,
    ILogger logger
) : PersistorBase<VerificationFlowFailure>(npgsqlDataSource, logger)
{
    protected override VerificationFlowFailure MapNpgsqlException(NpgsqlException ex)
    {
        return ex.SqlState switch
        {
            PostgreSqlErrorCodes.ConnectionException or
                PostgreSqlErrorCodes.ConnectionDoesNotExist or
                PostgreSqlErrorCodes.ConnectionFailure
                => VerificationFlowFailure.PersistorAccess(ex),

            PostgreSqlErrorCodes.SerializationFailure or
                PostgreSqlErrorCodes.UniqueViolation
                => VerificationFlowFailure.ConcurrencyConflict(),

            PostgreSqlErrorCodes.ForeignKeyViolation
                => VerificationFlowFailure.PersistorAccess(ex),

            PostgreSqlErrorCodes.CheckViolation or
                PostgreSqlErrorCodes.InvalidTextRepresentation
                => VerificationFlowFailure.Validation(),

            _ => VerificationFlowFailure.PersistorAccess(ex)
        };
    }

    protected override VerificationFlowFailure CreateTimeoutFailure(TimeoutException ex) =>
        VerificationFlowFailure.PersistorAccess(ex);

    protected override VerificationFlowFailure CreateGenericFailure(Exception ex) =>
        VerificationFlowFailure.Generic(VerificationFlowMessageKeys.Generic, ex);
}