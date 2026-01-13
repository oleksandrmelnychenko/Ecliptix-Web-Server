using System.Data.Common;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Actors.AccountProfile;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Microsoft.EntityFrameworkCore;
using Npgsql;

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
        ReceivePersistorCommand<GetAccountProfileActorEvent, Option<AccountProfileInfo>>(
            GetAccountProfileAsync, "GetAccountProfile");

        ReceivePersistorCommand<CheckProfileNameAvailabilityEvent, bool>(
            CheckProfileNameAvailabilityAsync, "CheckProfileNameAvailability");

        ReceivePersistorCommand<UpdateAccountProfileEvent, AccountProfileInfo>(
            UpdateAccountProfileAsync, "UpdateAccountProfile");
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, AccountProfileFailure>>> handler,
        string operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = message.CancellationToken;

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);

            return;

            Task<Result<TResult, AccountProfileFailure>> Operation(EcliptixSchemaContext ctx,
                CancellationToken cancellationToken) =>
                handler(ctx, message, cancellationToken);
        });
    }

    private static async Task<Result<Option<AccountProfileInfo>, AccountProfileFailure>> GetAccountProfileAsync(
        EcliptixSchemaContext ctx, GetAccountProfileActorEvent cmd, CancellationToken cancellationToken)
    {
        try
        {
            Option<AccountProfileEntity> profileOpt = Option<AccountProfileEntity>.None;

            switch (cmd.Criteria)
            {
                case SearchByMobile mobileCriteria:
                    profileOpt = await AccountProfileQueries.GetPrimaryAccountProfileByMobileNumber(
                        ctx, mobileCriteria.MobileNumber, cmd.CurrentAccountId);
                    break;

                case SearchById idCriteria:
                    profileOpt = await AccountProfileQueries.GetByAccountId(ctx, idCriteria.AccountId);
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
        EcliptixSchemaContext ctx, CheckProfileNameAvailabilityEvent cmd, CancellationToken cancellationToken)
    {
        try
        {
            bool isTaken = await AccountProfileQueries.IsProfileNameTaken(ctx, cmd.ProfileName);

            return Result<bool, AccountProfileFailure>.Ok(!isTaken);
        }
        catch (Exception ex)
        {
            return Result<bool, AccountProfileFailure>.Err(AccountProfileFailure.QueryFailed(ex));
        }
    }

    private static async Task<Result<AccountProfileInfo, AccountProfileFailure>> UpdateAccountProfileAsync(
        EcliptixSchemaContext ctx, UpdateAccountProfileEvent cmd, CancellationToken cancellationToken)
    {
        try
        {

            Option<AccountProfileEntity> profileOpt =
                await AccountProfileQueries.GetByAccountIdTracking(ctx, cmd.AccountId);

            AccountProfileEntity profile;

            if (profileOpt.IsSome)
            {
                profile = profileOpt.Value!;

                profile.ProfileName = cmd.ProfileName;
                profile.DisplayName = cmd.DisplayName;
                profile.UpdatedAt = DateTimeOffset.UtcNow;

            }
            else
            {
                bool accountExists = await ctx.Accounts
                    .AnyAsync(a => a.UniqueId == cmd.AccountId, cancellationToken);

                if (!accountExists)
                {
                    return Result<AccountProfileInfo, AccountProfileFailure>.Err(
                        AccountProfileFailure.NotFound("Account not found. Cannot create profile."));
                }

                profile = new AccountProfileEntity
                {
                    AccountId = cmd.AccountId,
                    ProfileName = cmd.ProfileName,
                    DisplayName = cmd.DisplayName,
                    UpdatedAt = DateTimeOffset.UtcNow,
                };

                ctx.AccountProfiles.Add(profile);
            }

            await ctx.SaveChangesAsync(cancellationToken);

            AccountProfileInfo resultInfo = new(
                profile.UniqueId,
                profile.AccountId,
                profile.ProfileName,
                profile.DisplayName
            );

            return Result<AccountProfileInfo, AccountProfileFailure>.Ok(resultInfo);
        }
        catch (DbUpdateException dbEx) when (dbEx.InnerException is PostgresException
                                             { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            return Result<AccountProfileInfo, AccountProfileFailure>.Err(
                AccountProfileFailure.AlreadyExists($"Profile name '{cmd.ProfileName}' is already taken."));
        }
        catch (Exception ex)
        {
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
