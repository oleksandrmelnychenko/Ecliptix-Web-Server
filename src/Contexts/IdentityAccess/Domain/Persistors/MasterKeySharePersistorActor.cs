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
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

public class MasterKeySharePersistorActor : PersistorBase<MasterKeyFailure>
{
    public MasterKeySharePersistorActor(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
        : base(dbContextFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        return Props.Create(() => new MasterKeySharePersistorActor(dbContextFactory));
    }

    private void Ready()
    {
        Receive<CreateMasterKeySharesCommand>(command =>
            ExecuteWithContext(
                    (schemaContext, cancellationToken) => InsertMasterKeySharesAsync(schemaContext, command, cancellationToken),
                    PersistorOperation.InsertMasterKeyShares,
                    command.CancellationToken)
                .PipeTo(Sender));

        Receive<GetMasterKeySharesQuery>(query =>
            ExecuteWithContext(
                    (schemaContext, cancellationToken) => GetMasterKeySharesByAccountIdAsync(schemaContext, query, cancellationToken),
                    PersistorOperation.GetMasterKeyShares,
                    query.CancellationToken)
                .PipeTo(Sender));

        Receive<DeleteMasterKeySharesCommand>(command =>
            ExecuteWithContext(
                    (schemaContext, cancellationToken) => DeleteMasterKeySharesAsync(schemaContext, command, cancellationToken),
                    PersistorOperation.DeleteMasterKeyShares,
                    command.CancellationToken)
                .PipeTo(Sender));
    }

    private static async Task<Result<InsertMasterKeySharesResult, MasterKeyFailure>> InsertMasterKeySharesAsync(
        EcliptixSchemaContext schemaContext,
        CreateMasterKeySharesCommand command,
        CancellationToken cancellationToken)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            if (command.Shares.Count == 0)
            {
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.NoSharesProvided());
            }

            Option<AccountEntity> accountOpt =
                await AccountQueries.GetAccountById(schemaContext, command.AccountUniqueId);
            if (!accountOpt.IsSome)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.InvalidIdentifier("Account not found or inactive"));
            }

            Option<CredentialsRecord> credentialsOpt =
                await AccountSecureKeyAuthQueries.GetCredentialsForAccount(schemaContext, command.AccountUniqueId);

            if (!credentialsOpt.IsSome)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.CredentialsNotFound());
            }

            CredentialsRecord credentials = credentialsOpt.Value!;
            int credentialsVersion = credentials.Version;

            List<MasterKeyShareEntity> existingShares =
                await MasterKeyShareQueries.GetByAccountId(schemaContext, command.AccountUniqueId,
                    cancellationToken);
            if (existingShares.Count != 0)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.SharesAlreadyExist());
            }

            int shareCount = command.Shares.Count;
            HashSet<int> seenIndexes = new(shareCount);
            int minIndex = int.MaxValue;
            int maxIndex = int.MinValue;

            for (int i = 0; i < shareCount; i++)
            {
                int shareIndex = command.Shares[i].ShareIndex;

                if (!seenIndexes.Add(shareIndex))
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                    return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                        MasterKeyFailure.DuplicateShareIndexes());
                }

                if (shareIndex < minIndex)
                {
                    minIndex = shareIndex;
                }

                if (shareIndex > maxIndex)
                {
                    maxIndex = shareIndex;
                }
            }

            if (minIndex != 1 || maxIndex != command.Shares.Count)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.KeySplittingFailed(
                        $"Share indexes must be sequential starting from 1 (expected 1-{command.Shares.Count}, got {minIndex}-{maxIndex})"));
            }

            List<MasterKeyShareEntity> sharesToInsert = new(shareCount);
            for (int i = 0; i < shareCount; i++)
            {
                ShareData share = command.Shares[i];
                sharesToInsert.Add(new MasterKeyShareEntity
                {
                    AccountId = command.AccountUniqueId,
                    ShareIndex = share.ShareIndex,
                    EncryptedShare = share.EncryptedShare,
                    ShareMetadata = share.ShareMetadata,
                    StorageLocation = share.StorageLocation,
                    CredentialsVersion = credentialsVersion
                });
            }

            schemaContext.MasterKeyShares.AddRange(sharesToInsert);
            await schemaContext.SaveChangesAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Ok(
                new InsertMasterKeySharesResult { Success = true, Message = "Shares inserted successfully" });
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                MasterKeyFailure.InsertFailed(ex.Message, ex));
        }
    }

    private static async Task<Result<MasterKeyShareQueryRecord[], MasterKeyFailure>>
        GetMasterKeySharesByAccountIdAsync(
            EcliptixSchemaContext schemaContext,
            GetMasterKeySharesQuery query,
            CancellationToken cancellationToken)
    {
        try
        {
            List<MasterKeyShareEntity> shares =
                await MasterKeyShareQueries.GetByAccountId(schemaContext, query.AccountUniqueId,
                    cancellationToken);

            if (shares.Count == 0)
            {
                return Result<MasterKeyShareQueryRecord[], MasterKeyFailure>.Err(
                    MasterKeyFailure.SharesNotFound());
            }

            MasterKeyShareQueryRecord[] queryRecords = new MasterKeyShareQueryRecord[shares.Count];
            for (int i = 0; i < shares.Count; i++)
            {
                MasterKeyShareEntity s = shares[i];
                queryRecords[i] = new MasterKeyShareQueryRecord
                {
                    AccountUniqueId = s.AccountId,
                    ShareIndex = s.ShareIndex,
                    EncryptedShare = s.EncryptedShare,
                    ShareMetadata = s.ShareMetadata,
                    StorageLocation = s.StorageLocation,
                    UniqueId = s.UniqueId,
                    CredentialsVersion = s.CredentialsVersion
                };
            }

            return Result<MasterKeyShareQueryRecord[], MasterKeyFailure>.Ok(queryRecords);
        }
        catch (Exception ex)
        {
            return Result<MasterKeyShareQueryRecord[], MasterKeyFailure>.Err(
                MasterKeyFailure.QueryFailed(ex));
        }
    }

    private static async Task<Result<Unit, MasterKeyFailure>> DeleteMasterKeySharesAsync(
        EcliptixSchemaContext schemaContext,
        DeleteMasterKeySharesCommand command,
        CancellationToken cancellationToken)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            await schemaContext.MasterKeyShares
                .Where(mks => mks.AccountId == command.AccountId && !mks.IsDeleted)
                .ExecuteDeleteAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);
            return Result<Unit, MasterKeyFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            return Result<Unit, MasterKeyFailure>.Err(
                MasterKeyFailure.DeleteFailed(ex));
        }
    }

    protected override MasterKeyFailure MapDbException(DbException ex)
    {
        if (ex is PostgresException pgEx)
        {
            return pgEx.SqlState switch
            {
                PostgresErrorCodes.UniqueViolation => MasterKeyFailure.KeySplittingFailed(
                    $"Duplicate share detected: {pgEx.MessageText}", pgEx),
                PostgresErrorCodes.ForeignKeyViolation => MasterKeyFailure.InvalidIdentifier(
                    $"Foreign key constraint violation: {pgEx.MessageText}"),
                PostgresErrorCodes.DeadlockDetected => MasterKeyFailure.DatabaseError(pgEx),
                PostgresErrorCodes.QueryCanceled => MasterKeyFailure.Timeout(pgEx),
                _ => MasterKeyFailure.DatabaseError(pgEx)
            };
        }

        return MasterKeyFailure.DatabaseError(ex);
    }

    protected override MasterKeyFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return MasterKeyFailure.Timeout(ex);
    }

    protected override MasterKeyFailure CreateGenericFailure(Exception ex)
    {
        return MasterKeyFailure.InternalError($"Unexpected error in master key share persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
