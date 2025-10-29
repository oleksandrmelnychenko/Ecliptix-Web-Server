using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.MasterKeyShares;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors;

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
        Receive<InsertMasterKeySharesEvent>(cmd =>
            ExecuteWithContext(
                    (ctx, cancellationToken) => InsertMasterKeySharesAsync(ctx, cmd, cancellationToken),
                    "InsertMasterKeyShares",
                    cmd.CancellationToken)
                .PipeTo(Sender));

        Receive<GetMasterKeySharesEvent>(cmd =>
            ExecuteWithContext(
                    (ctx, cancellationToken) => GetMasterKeySharesByMembershipIdAsync(ctx, cmd, cancellationToken),
                    "GetMasterKeyShares",
                    cmd.CancellationToken)
                .PipeTo(Sender));

        Receive<DeleteMasterKeySharesEvent>(cmd =>
            ExecuteWithContext(
                    (ctx, cancellationToken) => DeleteMasterKeySharesAsync(ctx, cmd, cancellationToken),
                    "DeleteMasterKeyShares",
                    cmd.CancellationToken)
                .PipeTo(Sender));
    }

    private static async Task<Result<InsertMasterKeySharesResult, MasterKeyFailure>> InsertMasterKeySharesAsync(
        EcliptixSchemaContext schemaContext,
        InsertMasterKeySharesEvent cmd,
        CancellationToken cancellationToken)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            if (cmd.Shares.Count == 0)
            {
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.NoSharesProvided());
            }

            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByUniqueId(schemaContext, cmd.MembershipUniqueId, cancellationToken);
            if (!membershipOpt.IsSome)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.MembershipNotFoundOrInactive());
            }

            MembershipEntity membership = membershipOpt.Value!;

            Option<AccountEntity> defaultAccountOpt =
                await AccountQueries.GetDefaultAccountByMembershipId(schemaContext, membership.UniqueId);

            if (!defaultAccountOpt.IsSome)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.DefaultAccountNotFound());
            }

            Option<CredentialsRecord> credentialsOpt =
                await AccountSecureKeyAuthQueries.GetCredentialsForAccount(schemaContext,
                    defaultAccountOpt.Value!.UniqueId);

            if (!credentialsOpt.IsSome)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.CredentialsNotFound());
            }

            CredentialsRecord credentials = credentialsOpt.Value;
            int credentialsVersion = credentials.Version;

            List<MasterKeyShareEntity> existingShares =
                await MasterKeyShareQueries.GetByMembershipUniqueId(schemaContext, cmd.MembershipUniqueId,
                    cancellationToken);
            if (existingShares.Count != 0)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.SharesAlreadyExist());
            }

            int shareCount = cmd.Shares.Count;
            HashSet<int> seenIndexes = new(shareCount);
            int minIndex = int.MaxValue;
            int maxIndex = int.MinValue;

            for (int i = 0; i < shareCount; i++)
            {
                int shareIndex = cmd.Shares[i].ShareIndex;

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

            if (minIndex != 1 || maxIndex != cmd.Shares.Count)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, MasterKeyFailure>.Err(
                    MasterKeyFailure.KeySplittingFailed(
                        $"Share indexes must be sequential starting from 1 (expected 1-{cmd.Shares.Count}, got {minIndex}-{maxIndex})"));
            }

            List<MasterKeyShareEntity> sharesToInsert = new(shareCount);
            for (int i = 0; i < shareCount; i++)
            {
                ShareData share = cmd.Shares[i];
                sharesToInsert.Add(new MasterKeyShareEntity
                {
                    MembershipUniqueId = cmd.MembershipUniqueId,
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
        GetMasterKeySharesByMembershipIdAsync(
            EcliptixSchemaContext schemaContext,
            GetMasterKeySharesEvent cmd,
            CancellationToken cancellationToken)
    {
        try
        {
            List<MasterKeyShareEntity> shares =
                await MasterKeyShareQueries.GetByMembershipUniqueId(schemaContext, cmd.MembershipUniqueId,
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
                    MembershipUniqueId = s.MembershipUniqueId,
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
        DeleteMasterKeySharesEvent cmd,
        CancellationToken cancellationToken)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            await schemaContext.MasterKeyShares
                .Where(mks => mks.MembershipUniqueId == cmd.MembershipId && !mks.IsDeleted)
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
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => MasterKeyFailure.KeySplittingFailed($"Duplicate share detected: {sqlEx.Message}", sqlEx),
                547 => MasterKeyFailure.InvalidIdentifier($"Foreign key constraint violation: {sqlEx.Message}"),
                1205 => MasterKeyFailure.DatabaseError(sqlEx),
                -2 => MasterKeyFailure.Timeout(sqlEx),
                2 => MasterKeyFailure.DatabaseError(sqlEx),
                18456 => MasterKeyFailure.DatabaseError(sqlEx),
                _ => MasterKeyFailure.DatabaseError(sqlEx)
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
