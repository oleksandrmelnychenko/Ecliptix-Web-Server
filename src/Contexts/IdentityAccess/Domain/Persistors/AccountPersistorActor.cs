using System.Data;
using System.Data.Common;
using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Actors;
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
            PersistorOperation.UpdateAccountSecureKey);

        ReceivePersistorCommand<EnsureAccountMaskingKeyCommand, AccountMaskingKeyEnsureResult>(
            EnsureAccountMaskingKeyAsync,
            PersistorOperation.EnsureAccountMaskingKey);

        ReceivePersistorCommand<CreateDefaultAccountCommand, AccountCreationResult>(
            CreateDefaultAccountAsync,
            PersistorOperation.CreateDefaultAccount);

        ReceivePersistorCommand<GetDefaultAccountIdQuery, Option<Guid>>(
            GetDefaultAccountIdAsync,
            PersistorOperation.GetDefaultAccountId);

        ReceivePersistorCommand<GetAccountsByMembershipIdQuery, List<AccountInfo>>(
            GetAccountsByMembershipIdAsync,
            PersistorOperation.GetAccountsByMembershipId);
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, AccountFailure>>> handler,
        PersistorOperation operationName)
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
        EcliptixSchemaContext schemaContext, UpdateAccountSecureKeyCommand command, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByUniqueId(schemaContext, command.MembershipIdentifier, cancellationToken);
            if (!membershipOpt.IsSome)
            {
                await transaction.RollbackAsync(cancellationToken);
                return Result<AccountSecureKeyUpdateResult, AccountFailure>.Err(
                    AccountFailure.ValidationFailed("Membership not found or inactive"));
            }

            MembershipEntity membership = membershipOpt.Value!;

            AccountEntity account;
            if (command.AccountId.HasValue)
            {
                Option<AccountEntity> accountOpt =
                    await AccountQueries.GetAccountById(schemaContext, command.AccountId.Value);
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
                        .SetProperty(a => a.SecureKey, command.SecureKey)
                        .SetProperty(a => a.MaskingKey, command.MaskingKey)
                        .SetProperty(a => a.CredentialsVersion, a => a.CredentialsVersion + 1)
                        .SetProperty(a => a.OpaqueKeyVersion, command.OpaqueKeyVersion)
                        .SetProperty(a => a.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);

                newCredentialsVersion = existingAuth.CredentialsVersion + 1;
            }
            else
            {
                AccountSecureKeyAuthEntity newAuth = new()
                {
                    AccountId = account.UniqueId,
                    SecureKey = command.SecureKey,
                    MaskingKey = command.MaskingKey,
                    CredentialsVersion = 1,
                    OpaqueKeyVersion = command.OpaqueKeyVersion,
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
                    command.MembershipIdentifier,
                    newCredentialsVersion,
                    command.OpaqueKeyVersion,
                    command.SecureKey,
                    command.MaskingKey));
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            return Result<AccountSecureKeyUpdateResult, AccountFailure>.Err(
                AccountFailure.CredentialUpdateFailed(ex));
        }
    }

    private static async Task<Result<AccountMaskingKeyEnsureResult, AccountFailure>> EnsureAccountMaskingKeyAsync(
        EcliptixSchemaContext schemaContext, EnsureAccountMaskingKeyCommand command,
        CancellationToken cancellationToken)
    {
        try
        {
            if (command.MaskingKey.Length != MembershipActorLimits.Opaque.MaskingKeyLength)
            {
                return Result<AccountMaskingKeyEnsureResult, AccountFailure>.Err(
                    AccountFailure.ValidationFailed(
                        $"Masking key must be {MembershipActorLimits.Opaque.MaskingKeyLength} bytes"));
            }

            Option<AccountEntity> accountOpt = await AccountQueries.GetAccountById(schemaContext, command.AccountId);
            if (!accountOpt.IsSome)
            {
                return Result<AccountMaskingKeyEnsureResult, AccountFailure>.Err(
                    AccountFailure.NotFoundById());
            }

            AccountEntity account = accountOpt.Value!;

            Option<AccountSecureKeyAuthEntity> authOpt =
                await AccountSecureKeyAuthQueries.GetPrimaryForAccount(schemaContext, account.UniqueId);

            if (!authOpt.IsSome)
            {
                return Result<AccountMaskingKeyEnsureResult, AccountFailure>.Err(
                    AccountFailure.ValidationFailed("Credentials not found for this account"));
            }

            AccountSecureKeyAuthEntity auth = authOpt.Value!;

            bool needsUpdate = auth.MaskingKey.Length != command.MaskingKey.Length ||
                               IsAllZero(auth.MaskingKey) ||
                               !CryptographicOperations.FixedTimeEquals(auth.MaskingKey, command.MaskingKey);

            int credentialsVersion = auth.CredentialsVersion;

            if (needsUpdate)
            {
                await schemaContext.AccountSecureKeyAuths
                    .Where(a => a.UniqueId == auth.UniqueId && !a.IsDeleted)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(a => a.MaskingKey, command.MaskingKey)
                        .SetProperty(a => a.CredentialsVersion, a => a.CredentialsVersion + 1)
                        .SetProperty(a => a.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);

                credentialsVersion = auth.CredentialsVersion + 1;
            }

            return Result<AccountMaskingKeyEnsureResult, AccountFailure>.Ok(
                new AccountMaskingKeyEnsureResult(
                    credentialsVersion,
                    needsUpdate));
        }
        catch (Exception ex)
        {
            return Result<AccountMaskingKeyEnsureResult, AccountFailure>.Err(
                AccountFailure.CredentialUpdateFailed(ex));
        }
        finally
        {
            if (command.MaskingKey != null)
            {
                CryptographicOperations.ZeroMemory(command.MaskingKey);
            }
        }
    }

    private static bool IsAllZero(byte[] data)
    {
        byte accumulator = data.Aggregate<byte, byte>(0, (current, value) => (byte)(current | value));

        return accumulator == 0;
    }

    private static async Task<Result<AccountCreationResult, AccountFailure>> CreateDefaultAccountAsync(
        EcliptixSchemaContext schemaContext, CreateDefaultAccountCommand command, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        try
        {
            AccountEntity personalAccount = new()
            {
                MembershipId = command.MembershipId,
                AccountType = Protobuf.Account.AccountType.Personal,
                Status = Protobuf.Account.AccountStatus.Active,
                IsDefaultAccount = true
            };

            if (command.AccountId.HasValue && command.AccountId.Value != Guid.Empty)
            {
                personalAccount.UniqueId = command.AccountId.Value;
            }

            schemaContext.Accounts.Add(personalAccount);

            await schemaContext.SaveChangesAsync(cancellationToken);

            List<AccountInfo> accounts =
            [
                new(
                    personalAccount.UniqueId,
                    command.MembershipId,
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
            Log.Error(ex, "Failed to create default account for MembershipId: {MembershipId}", command.MembershipId);
            return Result<AccountCreationResult, AccountFailure>.Err(
                AccountFailure.CreationFailed(ex));
        }
    }

    private static async Task<Result<Option<Guid>, AccountFailure>> GetDefaultAccountIdAsync(
        EcliptixSchemaContext schemaContext, GetDefaultAccountIdQuery query, CancellationToken cancellationToken)
    {
        try
        {
            Option<AccountEntity> accountOption =
                await AccountQueries.GetDefaultAccountByMembershipId(schemaContext, query.MembershipId);

            return Result<Option<Guid>, AccountFailure>.Ok(!accountOption.IsSome
                ? Option<Guid>.None
                : Option<Guid>.Some(accountOption.Value!.UniqueId));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get default account for MembershipId: {MembershipId}", query.MembershipId);
            return Result<Option<Guid>, AccountFailure>.Err(
                AccountFailure.QueryFailed(ex));
        }
    }

    private static async Task<Result<List<AccountInfo>, AccountFailure>> GetAccountsByMembershipIdAsync(
        EcliptixSchemaContext schemaContext, GetAccountsByMembershipIdQuery query, CancellationToken cancellationToken)
    {
        try
        {
            List<AccountInfo> accounts =
                await AccountQueries.GetAccountsByMembershipId(schemaContext, query.MembershipId, cancellationToken);
            return Result<List<AccountInfo>, AccountFailure>.Ok(accounts);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get accounts for MembershipId: {MembershipId}", query.MembershipId);
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
            // ignored
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
