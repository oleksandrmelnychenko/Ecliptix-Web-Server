using System.Data.Common;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

public abstract class PersistorBase<TFailure>(IDbContextFactory<EcliptixSchemaContext> dbContextFactory) : ReceiveActor
    where TFailure : IFailureBase
{
    protected IDbContextFactory<EcliptixSchemaContext> DbContextFactory { get; } = dbContextFactory;

    protected async Task<Result<TResult, TFailure>> ExecuteWithContext<TResult>(
        Func<EcliptixSchemaContext, CancellationToken, Task<Result<TResult, TFailure>>> operation,
        PersistorOperation operationName,
        CancellationToken cancellationToken = default)
    {
        TimeSpan operationTimeout = GetOperationTimeout(operationName);

        return await PersistorRetryPolicy.ExecuteWithRetryAsync(
            async token =>
            {
                await using EcliptixSchemaContext schemaContext = await DbContextFactory.CreateDbContextAsync(token);
                return await operation(schemaContext, token);
            },
            operationName,
            operationTimeout,
            (dbEx, _) => MapDbException(dbEx),
            (timeoutEx, _) => CreateTimeoutFailure(timeoutEx),
            (ex, _) => CreateGenericFailure(ex),
            cancellationToken);
    }

    private static TimeSpan GetOperationTimeout(PersistorOperation operation)
    {
        return operation switch
        {
            PersistorOperation.CreateMembership => TimeoutConfiguration.Database.CreateTimeout,
            PersistorOperation.CreateDefaultAccount => TimeoutConfiguration.Database.CreateTimeout,
            PersistorOperation.CreateVerificationFlow => TimeoutConfiguration.Database.CreateTimeout,
            PersistorOperation.CreateOtp => TimeoutConfiguration.Database.CreateTimeout,
            PersistorOperation.EnsureMobileNumber => TimeoutConfiguration.Database.CreateTimeout,
            PersistorOperation.RecordLogout => TimeoutConfiguration.Database.CreateTimeout,
            PersistorOperation.InsertMasterKeyShares => TimeoutConfiguration.Database.CreateTimeout,
            PersistorOperation.LogFailedAttempt => TimeoutConfiguration.Database.CreateTimeout,

            PersistorOperation.UpdateAccountSecureKey => TimeoutConfiguration.Database.UpdateTimeout,
            PersistorOperation.UpdateMembershipVerificationFlow => TimeoutConfiguration.Database.UpdateTimeout,
            PersistorOperation.UpdateMembershipCreationStatus => TimeoutConfiguration.Database.UpdateTimeout,
            PersistorOperation.UpdateVerificationFlowStatus => TimeoutConfiguration.Database.UpdateTimeout,
            PersistorOperation.UpdateOtpStatus => TimeoutConfiguration.Database.UpdateTimeout,
            PersistorOperation.UpdateAccountProfile => TimeoutConfiguration.Database.UpdateTimeout,
            PersistorOperation.ExpirePasswordRecoveryFlows => TimeoutConfiguration.Database.UpdateTimeout,
            PersistorOperation.IncrementOtpAttemptCount => TimeoutConfiguration.Database.UpdateTimeout,
            PersistorOperation.DeleteMasterKeyShares => TimeoutConfiguration.Database.UpdateTimeout,

            PersistorOperation.GetMembershipByVerificationFlow => TimeoutConfiguration.Database.GetTimeout,
            PersistorOperation.GetMembershipByUniqueId => TimeoutConfiguration.Database.GetTimeout,
            PersistorOperation.GetVerificationFlow => TimeoutConfiguration.Database.GetTimeout,
            PersistorOperation.GetOtp => TimeoutConfiguration.Database.GetTimeout,
            PersistorOperation.GetMobileNumber => TimeoutConfiguration.Database.GetTimeout,
            PersistorOperation.GetDefaultAccountId => TimeoutConfiguration.Database.GetTimeout,
            PersistorOperation.GetAccountProfile => TimeoutConfiguration.Database.GetTimeout,
            PersistorOperation.GetMostRecentLogout => TimeoutConfiguration.Database.GetTimeout,
            PersistorOperation.GetLogoutByDevice => TimeoutConfiguration.Database.GetTimeout,
            PersistorOperation.GetOtpAttemptCount => TimeoutConfiguration.Database.GetTimeout,

            PersistorOperation.LoginMembership => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.SignInMembership => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.ValidatePasswordRecoveryFlow => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.CheckMobileNumberAvailability => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.CheckExistingMembership => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.CheckProfileNameAvailability => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.GetAccountsByMembershipId => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.GetLogoutHistory => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.GetMasterKeyShares => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.InitiateVerificationFlow => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.RequestResendOtp => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.VerifyMobileForSecretKeyRecovery => TimeoutConfiguration.Database.QueryTimeout,
            PersistorOperation.QueryFlowStatusByConnectionId => TimeoutConfiguration.Database.QueryTimeout,

            // Device operations
            PersistorOperation.RegisterAppDevice => TimeoutConfiguration.Database.CreateTimeout,

            // Default fallback for any future operations
            _ => TimeoutConfiguration.Database.QueryTimeout
        };
    }

    protected abstract TFailure MapDbException(DbException ex);
    protected abstract TFailure CreateTimeoutFailure(TimeoutException ex);
    protected abstract TFailure CreateGenericFailure(Exception ex);

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
