using System.Data;
using System.Data.Common;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Actors.Membership;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Microsoft.EntityFrameworkCore.Storage;
using Serilog;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

public class AccountPersistorActor : PersistorBase<AccountFailure>
{
    public AccountPersistorActor(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
        : base(dbContextFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        return Props.Create(() => new AccountPersistorActor(dbContextFactory));
    }

    private void Ready()
    {
        ReceivePersistorCommand<UpdateAccountSecureKeyCommand, AccountSecureKeyUpdateResult>(
            UpdateAccountSecureKeyAsync,
            "UpdateAccountSecureKey");

        ReceivePersistorCommand<CreateDefaultAccountCommand, AccountCreationResult>(
            CreateDefaultAccountAsync,
            "CreateDefaultAccount");

        ReceivePersistorCommand<GetDefaultAccountIdQuery, Option<Guid>>(
            GetDefaultAccountIdAsync,
            "GetDefaultAccountId");

        ReceivePersistorCommand<GetAccountsByMembershipIdQuery, List<AccountInfo>>(
            GetAccountsByMembershipIdAsync,
            "GetAccountsByMembershipId");
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, AccountFailure>>> handler,
        string operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = ExtractCancellationToken(message);

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);

            return;

            Task<Result<TResult, AccountFailure>> Operation(EcliptixSchemaContext schemaContext,
                CancellationToken cancellationToken) =>
                handler(schemaContext, message, cancellationToken);
        });
    }

    private static CancellationToken ExtractCancellationToken(ICancellableActorEvent message) =>
        message.CancellationToken;

    private static async Task<Result<AccountSecureKeyUpdateResult, AccountFailure>> UpdateAccountSecureKeyAsync(
        EcliptixSchemaContext schemaContext, UpdateAccountSecureKeyCommand cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await schemaContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByUniqueId(schemaContext, cmd.MembershipIdentifier, cancellationToken);
            if (!membershipOpt.IsSome)
            {
                await transaction.RollbackAsync(cancellationToken);
                return Result<AccountSecureKeyUpdateResult, AccountFailure>.Err(
                    AccountFailure.ValidationFailed("Membership not found or inactive"));
            }

            MembershipEntity membership = membershipOpt.Value!;

            AccountEntity account;
            if (cmd.AccountId.HasValue)
            {
                Option<AccountEntity> accountOpt = await AccountQueries.GetAccountById(schemaContext, cmd.AccountId.Value);
                if (!accountOpt.IsSome)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Result<AccountSecureKeyUpdateResult, AccountFailure>.Err(
                        AccountFailure.NotFoundById());
                }

                account = accountOpt.Value!;
            }
            else
            {
                Option<AccountEntity> accountOpt =
                    await AccountQueries.GetDefaultAccountByMembershipId(schemaContext, membership.UniqueId);
                if (!accountOpt.IsSome)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Result<AccountSecureKeyUpdateResult, AccountFailure>.Err(
                        AccountFailure.NotFoundByMembership());
                }

                account = accountOpt.Value!;
            }

            if (account.MembershipId != membership.UniqueId)
            {
                await transaction.RollbackAsync(cancellationToken);
                return Result<AccountSecureKeyUpdateResult, AccountFailure>.Err(
                    AccountFailure.ValidationFailed("Account does not belong to membership"));
            }

            Option<AccountSecureKeyAuthEntity> authOpt =
                await AccountSecureKeyAuthQueries.GetPrimaryForAccount(schemaContext, account.UniqueId);

            int newCredentialsVersion;

            if (authOpt.IsSome)
            {
                AccountSecureKeyAuthEntity existingAuth = authOpt.Value!;
                await schemaContext.AccountSecureKeyAuths
                    .Where(a => a.UniqueId == existingAuth.UniqueId && !a.IsDeleted)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(a => a.SecureKey, cmd.SecureKey)
                        .SetProperty(a => a.MaskingKey, cmd.MaskingKey)
                        .SetProperty(a => a.CredentialsVersion, a => a.CredentialsVersion + 1)
                        .SetProperty(a => a.OpaqueKeyVersion, cmd.OpaqueKeyVersion)
                        .SetProperty(a => a.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);

                newCredentialsVersion = existingAuth.CredentialsVersion + 1;
            }
            else
            {
                AccountSecureKeyAuthEntity newAuth = new()
                {
                    AccountId = account.UniqueId,
                    SecureKey = cmd.SecureKey,
                    MaskingKey = cmd.MaskingKey,
                    CredentialsVersion = 1,
                    OpaqueKeyVersion = cmd.OpaqueKeyVersion,
                    IsPrimary = true,
                    IsEnabled = true
                };
                schemaContext.AccountSecureKeyAuths.Add(newAuth);
                newCredentialsVersion = 1;
            }

            await schemaContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return Result<AccountSecureKeyUpdateResult, AccountFailure>.Ok(
                new AccountSecureKeyUpdateResult(
                    account.UniqueId,
                    cmd.MembershipIdentifier,
                    newCredentialsVersion,
                    cmd.OpaqueKeyVersion,
                    cmd.SecureKey,
                    cmd.MaskingKey));
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            return Result<AccountSecureKeyUpdateResult, AccountFailure>.Err(
                AccountFailure.CredentialUpdateFailed(ex));
        }
    }

    private static async Task<Result<AccountCreationResult, AccountFailure>> CreateDefaultAccountAsync(
        EcliptixSchemaContext schemaContext, CreateDefaultAccountCommand cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await schemaContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            AccountEntity personalAccount = new()
            {
                MembershipId = cmd.MembershipId,
                AccountType = Protobuf.Account.AccountType.Personal,
                Status = Protobuf.Account.AccountStatus.Active,
                IsDefaultAccount = true
            };

            if (cmd.AccountId.HasValue && cmd.AccountId.Value != Guid.Empty)
            {
                personalAccount.UniqueId = cmd.AccountId.Value;
            }

            schemaContext.Accounts.Add(personalAccount);

            await schemaContext.SaveChangesAsync(cancellationToken);

            List<AccountInfo> accounts =
            [
                new(
                    personalAccount.UniqueId,
                    cmd.MembershipId,
                    Protobuf.Account.AccountType.Personal,
                    true,
                    Protobuf.Account.AccountStatus.Active)
            ];

            await transaction.CommitAsync(cancellationToken);
            return Result<AccountCreationResult, AccountFailure>.Ok(
                new AccountCreationResult(accounts, accounts[0]));
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            Log.Error(ex, "Failed to create default account for MembershipId: {MembershipId}", cmd.MembershipId);
            return Result<AccountCreationResult, AccountFailure>.Err(
                AccountFailure.CreationFailed(ex));
        }
    }

    private static async Task<Result<Option<Guid>, AccountFailure>> GetDefaultAccountIdAsync(
        EcliptixSchemaContext schemaContext, GetDefaultAccountIdQuery cmd, CancellationToken cancellationToken)
    {
        try
        {
            Option<AccountEntity> accountOption =
                await AccountQueries.GetDefaultAccountByMembershipId(schemaContext, cmd.MembershipId);

            return Result<Option<Guid>, AccountFailure>.Ok(!accountOption.IsSome
                ? Option<Guid>.None
                : Option<Guid>.Some(accountOption.Value!.UniqueId));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get default account for MembershipId: {MembershipId}", cmd.MembershipId);
            return Result<Option<Guid>, AccountFailure>.Err(
                AccountFailure.QueryFailed(ex));
        }
    }

    private static async Task<Result<List<AccountInfo>, AccountFailure>> GetAccountsByMembershipIdAsync(
        EcliptixSchemaContext schemaContext, GetAccountsByMembershipIdQuery cmd, CancellationToken cancellationToken)
    {
        try
        {
            List<AccountInfo> accounts =
                await AccountQueries.GetAccountsByMembershipId(schemaContext, cmd.MembershipId, cancellationToken);
            return Result<List<AccountInfo>, AccountFailure>.Ok(accounts);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get accounts for MembershipId: {MembershipId}", cmd.MembershipId);
            return Result<List<AccountInfo>, AccountFailure>.Err(
                AccountFailure.QueryFailed(ex));
        }
    }

    private static async Task RollbackSilentlyAsync(IDbContextTransaction transaction)
    {
        try
        {
            await transaction.RollbackAsync(CancellationToken.None);
        }
        catch
        {

        }
    }

    protected override AccountFailure MapDbException(DbException ex)
    {
        if (ex is PostgresException pgEx)
        {
            return pgEx.SqlState switch
            {
                PostgresErrorCodes.UniqueViolation =>
                    AccountFailure.AlreadyExists($"Duplicate account detected: {pgEx.MessageText}"),
                PostgresErrorCodes.ForeignKeyViolation =>
                    AccountFailure.ValidationFailed($"Foreign key constraint violation: {pgEx.MessageText}"),
                PostgresErrorCodes.DeadlockDetected => AccountFailure.DatabaseError(pgEx),
                PostgresErrorCodes.QueryCanceled => AccountFailure.Timeout(pgEx),
                _ => AccountFailure.DatabaseError(pgEx)
            };
        }

        return AccountFailure.DatabaseError(ex);
    }

    protected override AccountFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return AccountFailure.Timeout(ex);
    }

    protected override AccountFailure CreateGenericFailure(Exception ex)
    {
        return AccountFailure.InternalError($"Unexpected error in account persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
