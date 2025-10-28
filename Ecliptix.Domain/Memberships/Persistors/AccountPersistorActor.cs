using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Account;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

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
        ReceivePersistorCommand<UpdateAccountSecureKeyEvent, AccountSecureKeyUpdateResult>(
            UpdateAccountSecureKeyAsync,
            "UpdateAccountSecureKey");

        ReceivePersistorCommand<CreateDefaultAccountEvent, AccountCreationResult>(
            CreateDefaultAccountAsync,
            "CreateDefaultAccount");

        ReceivePersistorCommand<GetDefaultAccountIdEvent, Option<Guid>>(
            GetDefaultAccountIdAsync,
            "GetDefaultAccountId");
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

            Task<Result<TResult, AccountFailure>> Operation(EcliptixSchemaContext ctx,
                CancellationToken cancellationToken) =>
                handler(ctx, message, cancellationToken);
        });
    }

    private static CancellationToken ExtractCancellationToken(ICancellableActorEvent message) =>
        message.CancellationToken;

    private static async Task<Result<AccountSecureKeyUpdateResult, AccountFailure>> UpdateAccountSecureKeyAsync(
        EcliptixSchemaContext ctx, UpdateAccountSecureKeyEvent cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByUniqueId(ctx, cmd.MembershipIdentifier, cancellationToken);
            if (!membershipOpt.HasValue)
            {
                await transaction.RollbackAsync(cancellationToken);
                return Result<AccountSecureKeyUpdateResult, AccountFailure>.Err(
                    AccountFailure.ValidationFailed("Membership not found or inactive"));
            }

            MembershipEntity membership = membershipOpt.Value!;

            AccountEntity account;
            if (cmd.AccountId.HasValue)
            {
                Option<AccountEntity> accountOpt = await AccountQueries.GetAccountById(ctx, cmd.AccountId.Value);
                if (!accountOpt.HasValue)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Result<AccountSecureKeyUpdateResult, AccountFailure>.Err(
                        AccountFailure.NotFoundById());
                }

                account = accountOpt!.Value;
            }
            else
            {
                Option<AccountEntity> accountOpt =
                    await AccountQueries.GetDefaultAccountByMembershipId(ctx, membership.UniqueId);
                if (!accountOpt.HasValue)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Result<AccountSecureKeyUpdateResult, AccountFailure>.Err(
                        AccountFailure.NotFoundByMembership());
                }

                account = accountOpt.Value!;
            }

            Option<AccountSecureKeyAuthEntity> authOpt =
                await AccountSecureKeyAuthQueries.GetPrimaryForAccount(ctx, account.UniqueId);

            int newCredentialsVersion;

            if (authOpt.HasValue)
            {
                AccountSecureKeyAuthEntity existingAuth = authOpt.Value;
                await ctx.AccountSecureKeyAuths
                    .Where(a => a.UniqueId == existingAuth.UniqueId && !a.IsDeleted)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(a => a.SecureKey, cmd.SecureKey)
                        .SetProperty(a => a.MaskingKey, cmd.MaskingKey)
                        .SetProperty(a => a.CredentialsVersion, a => a.CredentialsVersion + 1)
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
                    IsPrimary = true,
                    IsEnabled = true
                };
                ctx.AccountSecureKeyAuths.Add(newAuth);
                newCredentialsVersion = 1;
            }

            await ctx.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return Result<AccountSecureKeyUpdateResult, AccountFailure>.Ok(
                new AccountSecureKeyUpdateResult(
                    account.UniqueId,
                    cmd.MembershipIdentifier,
                    newCredentialsVersion,
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
        EcliptixSchemaContext ctx, CreateDefaultAccountEvent cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            AccountEntity personalAccount = new()
            {
                MembershipId = cmd.MembershipId,
                AccountType = Protobuf.Account.AccountType.Personal,
                AccountName = "Personal",
                Status = Protobuf.Account.AccountStatus.Active,
                IsDefaultAccount = true
            };

            ctx.Accounts.Add(personalAccount);
            await ctx.SaveChangesAsync(cancellationToken);

            List<AccountInfo> accounts =
            [
                new(
                    personalAccount.UniqueId,
                    cmd.MembershipId,
                    Protobuf.Account.AccountType.Personal,
                    "Personal",
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
        EcliptixSchemaContext ctx, GetDefaultAccountIdEvent cmd, CancellationToken cancellationToken)
    {
        try
        {
            Option<AccountEntity> accountOption =
                await AccountQueries.GetDefaultAccountByMembershipId(ctx, cmd.MembershipId);

            return Result<Option<Guid>, AccountFailure>.Ok(!accountOption.HasValue
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
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => AccountFailure.AlreadyExists($"Duplicate account detected: {sqlEx.Message}"),
                547 => AccountFailure.ValidationFailed($"Foreign key constraint violation: {sqlEx.Message}"),
                1205 => AccountFailure.DatabaseError(sqlEx),
                -2 => AccountFailure.Timeout(sqlEx),
                2 => AccountFailure.DatabaseError(sqlEx),
                18456 => AccountFailure.DatabaseError(sqlEx),
                _ => AccountFailure.DatabaseError(sqlEx)
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

public record AccountSecureKeyUpdateResult(
    Guid AccountId,
    Guid MembershipId,
    int CredentialsVersion,
    byte[] SecureKey,
    byte[] MaskingKey);
