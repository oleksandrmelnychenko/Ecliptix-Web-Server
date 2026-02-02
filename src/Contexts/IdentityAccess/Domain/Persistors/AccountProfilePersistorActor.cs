using System.Data.Common;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Actors.AccountProfile;
using Ecliptix.IdentityAccess.Domain.Memberships;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using Serilog;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

public class AccountProfilePersistorActor : PersistorBase<AccountProfileFailure>
{
    public AccountProfilePersistorActor(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
        : base(dbContextFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        return Props.Create(() => new AccountProfilePersistorActor(dbContextFactory));
    }

    private void Ready()
    {
        ReceivePersistorCommand<GetAccountProfileQuery, Option<AccountProfileInfo>>(
            GetAccountProfileAsync, PersistorOperation.GetAccountProfile);

        ReceivePersistorCommand<ExistsProfileNameQuery, bool>(
            CheckProfileNameAvailabilityAsync, PersistorOperation.CheckProfileNameAvailability);

        ReceivePersistorCommand<UpdateAccountProfileCommand, AccountProfileInfo>(
            UpdateAccountProfileAsync, PersistorOperation.UpdateAccountProfile);
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, AccountProfileFailure>>> handler,
        PersistorOperation operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = message.CancellationToken;

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);

            return;

            Task<Result<TResult, AccountProfileFailure>> Operation(EcliptixSchemaContext schemaContext,
                CancellationToken cancellationToken) =>
                handler(schemaContext, message, cancellationToken);
        });
    }

    private static async Task<Result<Option<AccountProfileInfo>, AccountProfileFailure>> GetAccountProfileAsync(
        EcliptixSchemaContext schemaContext, GetAccountProfileQuery query, CancellationToken cancellationToken)
    {
        try
        {
            Option<AccountProfileEntity> profileOpt = Option<AccountProfileEntity>.None;

            switch (query.Criteria)
            {
                case SearchByMobile mobileCriteria:
                    profileOpt = await AccountProfileQueries.GetPrimaryAccountProfileByMobileNumber(
                        schemaContext, mobileCriteria.MobileNumber, query.CurrentAccountId);
                    break;

                case SearchById idCriteria:
                    profileOpt = await AccountProfileQueries.GetByAccountId(schemaContext, idCriteria.AccountId);
                    break;
            }

            if (!profileOpt.IsSome)
            {
                return Result<Option<AccountProfileInfo>, AccountProfileFailure>.Ok(Option<AccountProfileInfo>.None);
            }

            AccountProfileEntity entity = profileOpt.Value!;

            AccountProfileInfo profileInfo = new(
                entity.UniqueId,
                entity.AccountId,
                entity.ProfileName,
                entity.DisplayName
            );

            return Result<Option<AccountProfileInfo>, AccountProfileFailure>.Ok(Option<AccountProfileInfo>.Some(profileInfo));
        }
        catch (Exception ex)
        {
            return Result<Option<AccountProfileInfo>, AccountProfileFailure>.Err(AccountProfileFailure.QueryFailed(ex));
        }
    }

    private static async Task<Result<bool, AccountProfileFailure>> CheckProfileNameAvailabilityAsync(
        EcliptixSchemaContext schemaContext, ExistsProfileNameQuery query, CancellationToken cancellationToken)
    {
        try
        {
            bool isTaken = await AccountProfileQueries.IsProfileNameTaken(schemaContext, query.ProfileName);

            return Result<bool, AccountProfileFailure>.Ok(!isTaken);
        }
        catch (Exception ex)
        {
            return Result<bool, AccountProfileFailure>.Err(AccountProfileFailure.QueryFailed(ex));
        }
    }

    private static async Task<Result<AccountProfileInfo, AccountProfileFailure>> UpdateAccountProfileAsync(
        EcliptixSchemaContext schemaContext,
        UpdateAccountProfileCommand command,
        CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted, cancellationToken);

        try
        {
            Option<AccountProfileEntity> profileOpt =
                await AccountProfileQueries.GetByAccountIdTracking(schemaContext, command.AccountId);

            AccountProfileEntity profile;
            Guid membershipId;

            if (profileOpt.IsSome)
            {
                profile = profileOpt.Value!;
                profile.ProfileName = command.ProfileName;
                profile.DisplayName = command.DisplayName;
                profile.UpdatedAt = DateTimeOffset.UtcNow;

                Option<Guid> membershipIdOpt = await AccountProfileQueries.GetMembershipIdByAccountId(
                    schemaContext, command.AccountId);

                if (!membershipIdOpt.IsSome)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Result<AccountProfileInfo, AccountProfileFailure>.Err(
                        AccountProfileFailure.NotFound("Account integrity error."));
                }
                membershipId = membershipIdOpt.Value;
            }
            else
            {
                AccountEntity? account = await schemaContext.Accounts
                    .FirstOrDefaultAsync(a => a.UniqueId == command.AccountId, cancellationToken);

                if (account == null)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Result<AccountProfileInfo, AccountProfileFailure>.Err(
                        AccountProfileFailure.NotFound("Account not found."));
                }

                profile = new AccountProfileEntity
                {
                    AccountId = command.AccountId,
                    ProfileName = command.ProfileName,
                    DisplayName = command.DisplayName,
                    UpdatedAt = DateTimeOffset.UtcNow,
                };

                schemaContext.AccountProfiles.Add(profile);
                membershipId = account.MembershipId;
            }

            Option<MembershipCreationStatus> currentStatusOpt =
                await MembershipQueries.GetCreationStatusById(schemaContext, membershipId);

            if (!currentStatusOpt.IsSome)
            {
                await transaction.RollbackAsync(cancellationToken);
                return Result<AccountProfileInfo, AccountProfileFailure>.Err(
                    AccountProfileFailure.InternalError("Membership missing for account."));
            }

            MembershipCreationStatus currentStatus = currentStatusOpt.Value;
            MembershipCreationStatus targetStatus = MembershipCreationStatus.ProfileSet;

            if (currentStatus < targetStatus)
            {
                Log.Information("Promoting Membership {Id} status from {Old} to ProfileSet",
                    membershipId, currentStatus);

                int affected = await schemaContext.Memberships
                    .Where(m => m.UniqueId == membershipId)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(m => m.CreationStatus, targetStatus)
                        .SetProperty(m => m.UpdatedAt, DateTimeOffset.UtcNow),
                        cancellationToken);

                if (affected == 0)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Result<AccountProfileInfo, AccountProfileFailure>.Err(
                        AccountProfileFailure.InternalError("Failed to update membership status."));
                }
            }

            await schemaContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return Result<AccountProfileInfo, AccountProfileFailure>.Ok(new AccountProfileInfo(
                profile.UniqueId,
                profile.AccountId,
                profile.ProfileName,
                profile.DisplayName
            ));
        }
        catch (DbUpdateException dbEx) when (dbEx.InnerException is PostgresException
                                             { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            await transaction.RollbackAsync(cancellationToken);
            return Result<AccountProfileInfo, AccountProfileFailure>.Err(
                AccountProfileFailure.AlreadyExists($"Profile name '{command.ProfileName}' is already taken."));
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(cancellationToken);
            return Result<AccountProfileInfo, AccountProfileFailure>.Err(AccountProfileFailure.DatabaseError(ex));
        }
    }


    protected override AccountProfileFailure MapDbException(DbException ex)
    {
        if (ex is PostgresException pgEx)
        {
            return pgEx.SqlState switch
            {
                PostgresErrorCodes.UniqueViolation =>
                    AccountProfileFailure.AlreadyExists($"Duplicate profile detected: {pgEx.MessageText}"),
                PostgresErrorCodes.ForeignKeyViolation =>
                    AccountProfileFailure.ValidationFailed($"Foreign key constraint violation: {pgEx.MessageText}"),
                PostgresErrorCodes.DeadlockDetected => AccountProfileFailure.DatabaseError(pgEx),
                PostgresErrorCodes.QueryCanceled => AccountProfileFailure.Timeout(pgEx),
                _ => AccountProfileFailure.DatabaseError(pgEx)
            };
        }

        return AccountProfileFailure.DatabaseError(ex);
    }

    protected override AccountProfileFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return AccountProfileFailure.Timeout(ex);
    }

    protected override AccountProfileFailure CreateGenericFailure(Exception ex)
    {
        return AccountProfileFailure.InternalError($"Unexpected error in profile persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
