using System.Data;
using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Schema;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public abstract class PersistorBase<TFailure> : ReceiveActor
    where TFailure : IFailureBase
{
    private readonly IDbContextFactory<EcliptixSchemaContext> _dbContextFactory;

    protected PersistorBase(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        _dbContextFactory = dbContextFactory;
        GetOperationTimeouts();
    }

    protected async Task<Result<TResult, TFailure>> ExecuteWithContext<TResult>(
        Func<EcliptixSchemaContext, Task<Result<TResult, TFailure>>> operation,
        string operationName)
    {
        return await PersistorRetryPolicy.ExecuteWithRetryAsync(
            async () =>
            {
                await using EcliptixSchemaContext ctx = await _dbContextFactory.CreateDbContextAsync();
                return await operation(ctx);
            },
            operationName,
            (dbEx, opName) => MapDbException(dbEx),
            (timeoutEx, opName) => CreateTimeoutFailure(timeoutEx),
            (ex, opName) => CreateGenericFailure(ex));
    }

    protected abstract TFailure MapDbException(DbException ex);
    protected abstract TFailure CreateTimeoutFailure(TimeoutException ex);
    protected abstract TFailure CreateGenericFailure(Exception ex);

    private static Dictionary<string, TimeSpan> GetOperationTimeouts()
    {
        return new Dictionary<string, TimeSpan>
        {
            ["Create"] = TimeoutConfiguration.Database.CreateTimeout,
            ["Update"] = TimeoutConfiguration.Database.UpdateTimeout,
            ["Delete"] = TimeoutConfiguration.Database.DeleteTimeout,
            ["Get"] = TimeoutConfiguration.Database.GetTimeout,
            ["Query"] = TimeoutConfiguration.Database.QueryTimeout,
            ["List"] = TimeoutConfiguration.Database.ListTimeout
        };
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}