using System.Data.Common;
using System.Threading;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors;

public class MasterKeySharePersistorActor : PersistorBase<KeySplittingFailure>
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
                    (ctx, ct) => InsertMasterKeySharesAsync(ctx, cmd, ct),
                    "InsertMasterKeyShares",
                    cmd.CancellationToken)
                .PipeTo(Sender));

        Receive<GetMasterKeySharesEvent>(cmd =>
            ExecuteWithContext(
                    (ctx, ct) => GetMasterKeySharesByMembershipIdAsync(ctx, cmd, ct),
                    "GetMasterKeyShares",
                    cmd.CancellationToken)
                .PipeTo(Sender));

        Receive<DeleteMasterKeySharesEvent>(cmd =>
            ExecuteWithContext(
                    (ctx, ct) => DeleteMasterKeySharesAsync(ctx, cmd, ct),
                    "DeleteMasterKeyShares",
                    cmd.CancellationToken)
                .PipeTo(Sender));
    }

    private static async Task<Result<InsertMasterKeySharesResult, KeySplittingFailure>> InsertMasterKeySharesAsync(
        EcliptixSchemaContext ctx,
        InsertMasterKeySharesEvent cmd,
        CancellationToken cancellationToken)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            if (cmd.Shares.Count == 0)
            {
                return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeySplittingFailed("No shares provided"));
            }

            MembershipEntity? membership = await MembershipQueries.GetByUniqueId(ctx, cmd.MembershipUniqueId, cancellationToken);
            if (membership == null)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.InvalidIdentifier("Membership not found or inactive"));
            }

            List<MasterKeyShareEntity> existingShares =
                await MasterKeyShareQueries.GetByMembershipUniqueId(ctx, cmd.MembershipUniqueId, cancellationToken);
            if (existingShares.Any())
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeySplittingFailed("Master key shares already exist for this membership"));
            }

            int distinctIndexes = cmd.Shares.Select(s => s.ShareIndex).Distinct().Count();
            if (distinctIndexes != cmd.Shares.Count)
            {
                await transaction.RollbackAsync();
                return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeySplittingFailed("Duplicate share indexes detected"));
            }

            int maxIndex = cmd.Shares.Max(s => s.ShareIndex);
            int minIndex = cmd.Shares.Min(s => s.ShareIndex);
            if (minIndex != 1 || maxIndex != cmd.Shares.Count)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeySplittingFailed($"Share indexes must be sequential starting from 1 (expected 1-{cmd.Shares.Count}, got {minIndex}-{maxIndex})"));
            }

            List<MasterKeyShareEntity> sharesToInsert = cmd.Shares.Select(s => new MasterKeyShareEntity
            {
                MembershipUniqueId = cmd.MembershipUniqueId,
                ShareIndex = s.ShareIndex,
                EncryptedShare = s.EncryptedShare,
                ShareMetadata = s.ShareMetadata,
                StorageLocation = s.StorageLocation,
                CredentialsVersion = membership.CredentialsVersion
            }).ToList();

            ctx.MasterKeyShares.AddRange(sharesToInsert);
            await ctx.SaveChangesAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Ok(
                new InsertMasterKeySharesResult
                {
                    Success = true,
                    Message = "Shares inserted successfully"
                });
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed($"Insert failed: {ex.Message}"));
        }
    }

    private static async Task<Result<MasterKeyShareQueryRecord[], KeySplittingFailure>> GetMasterKeySharesByMembershipIdAsync(
        EcliptixSchemaContext ctx,
        GetMasterKeySharesEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            List<MasterKeyShareEntity> shares = await MasterKeyShareQueries.GetByMembershipUniqueId(ctx, cmd.MembershipUniqueId, cancellationToken);

            if (shares.Count == 0)
            {
                return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                    KeySplittingFailure.InsufficientShares(0, 1));
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

            return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Ok(queryRecords);
        }
        catch (Exception ex)
        {
            return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed($"Get shares failed: {ex.Message}"));
        }
    }

    private static async Task<Result<Unit, KeySplittingFailure>> DeleteMasterKeySharesAsync(
        EcliptixSchemaContext ctx,
        DeleteMasterKeySharesEvent cmd,
        CancellationToken cancellationToken)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            await ctx.MasterKeyShares
                .Where(mks => mks.MembershipUniqueId == cmd.MembershipId && !mks.IsDeleted)
                .ExecuteDeleteAsync(cancellationToken);

            await transaction.CommitAsync(cancellationToken);
            return Result<Unit, KeySplittingFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            return Result<Unit, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed($"Delete shares failed: {ex.Message}"));
        }
    }

    protected override KeySplittingFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => KeySplittingFailure.KeySplittingFailed($"Duplicate share detected: {sqlEx.Message}"),
                547 => KeySplittingFailure.InvalidIdentifier($"Foreign key constraint violation: {sqlEx.Message}"),
                1205 => KeySplittingFailure.KeySplittingFailed($"Deadlock detected: {sqlEx.Message}"),
                -2 => KeySplittingFailure.KeySplittingFailed("Command timeout occurred", sqlEx),
                2 => KeySplittingFailure.KeySplittingFailed("Network error occurred", sqlEx),
                18456 => KeySplittingFailure.KeySplittingFailed("Authentication failed", sqlEx),
                _ => KeySplittingFailure.KeySplittingFailed($"Database error (Code: {sqlEx.Number}): {sqlEx.Message}", sqlEx)
            };
        }

        return KeySplittingFailure.KeySplittingFailed("Database operation failed", ex);
    }

    protected override KeySplittingFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return KeySplittingFailure.KeySplittingFailed("Database operation timed out", ex);
    }

    protected override KeySplittingFailure CreateGenericFailure(Exception ex)
    {
        return KeySplittingFailure.KeySplittingFailed($"Unexpected error in master key share persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
