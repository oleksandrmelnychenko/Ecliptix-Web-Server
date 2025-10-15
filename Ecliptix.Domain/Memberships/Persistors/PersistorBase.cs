using System.Data.Common;
using System.Threading;
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

    protected Task<Result<TResult, TFailure>> ExecuteWithContext<TResult>(
        Func<EcliptixSchemaContext, Task<Result<TResult, TFailure>>> operation,
        string operationName) =>
        ExecuteWithContext((ctx, _) => operation(ctx), operationName, CancellationToken.None);

    protected async Task<Result<TResult, TFailure>> ExecuteWithContext<TResult>(
        Func<EcliptixSchemaContext, CancellationToken, Task<Result<TResult, TFailure>>> operation,
        string operationName,
        CancellationToken cancellationToken = default)
    {
        TimeSpan operationTimeout = GetOperationTimeout(operationName);

        return await PersistorRetryPolicy.ExecuteWithRetryAsync(
            async (ct) =>
            {
                await using EcliptixSchemaContext ctx = await _dbContextFactory.CreateDbContextAsync(ct);
                return await operation(ctx, ct);
            },
            operationName,
            operationTimeout,
            (dbEx, opName) => MapDbException(dbEx),
            (timeoutEx, opName) => CreateTimeoutFailure(timeoutEx),
            (ex, opName) => CreateGenericFailure(ex),
            cancellationToken);
    }

    private static TimeSpan GetOperationTimeout(string operationName)
    {
        return operationName switch
        {
            "CreateMembership" => TimeoutConfiguration.Database.CreateTimeout,
            "UpdateMembershipSecureKey" => TimeoutConfiguration.Database.UpdateTimeout,
            "LoginMembership" => TimeoutConfiguration.Database.QueryTimeout,
            "SignInMembership" => TimeoutConfiguration.Database.QueryTimeout,
            "GetMembershipByVerificationFlow" => TimeoutConfiguration.Database.GetTimeout,
            "GetMembershipByUniqueId" => TimeoutConfiguration.Database.GetTimeout,
            "CreateDefaultAccount" => TimeoutConfiguration.Database.CreateTimeout,
            "ValidatePasswordRecoveryFlow" => TimeoutConfiguration.Database.QueryTimeout,
            "ExpirePasswordRecoveryFlows" => TimeoutConfiguration.Database.UpdateTimeout,
            "UpdateMembershipVerificationFlow" => TimeoutConfiguration.Database.UpdateTimeout,
            "CreateOtp" => TimeoutConfiguration.Database.CreateTimeout,
            "UpdateOtpStatus" => TimeoutConfiguration.Database.UpdateTimeout,
            "GetOtp" => TimeoutConfiguration.Database.GetTimeout,
            "CreateVerificationFlow" => TimeoutConfiguration.Database.CreateTimeout,
            "UpdateVerificationFlowStatus" => TimeoutConfiguration.Database.UpdateTimeout,
            "GetVerificationFlow" => TimeoutConfiguration.Database.GetTimeout,
            "EnsureMobileNumber" => TimeoutConfiguration.Database.CreateTimeout,
            "GetMobileNumber" => TimeoutConfiguration.Database.GetTimeout,
            "RecordLogout" => TimeoutConfiguration.Database.CreateTimeout,
            _ => TimeoutConfiguration.Database.CommandTimeout
        };
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
