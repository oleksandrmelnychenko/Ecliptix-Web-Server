using System.Data;
using System.Data.Common;
using Akka.Actor;
using Dapper;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;
using Microsoft.Data.SqlClient;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public class MasterKeySharePersistorActor : PersistorBase<KeySplittingFailure>
{
    public MasterKeySharePersistorActor(IDbConnectionFactory connectionFactory)
        : base(connectionFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbConnectionFactory connectionFactory)
    {
        return Props.Create(() => new MasterKeySharePersistorActor(connectionFactory));
    }

    private void Ready()
    {
        Receive<InsertMasterKeySharesEvent>(cmd =>
            ExecuteWithConnection(conn => InsertMasterKeySharesAsync(conn, cmd), "InsertMasterKeyShares")
                .PipeTo(Sender));

        Receive<GetMasterKeySharesEvent>(cmd =>
            ExecuteWithConnection(conn => GetMasterKeySharesByMembershipIdAsync(conn, cmd), "GetMasterKeyShares")
                .PipeTo(Sender));
    }

    private static async Task<Result<InsertMasterKeySharesResult, KeySplittingFailure>> InsertMasterKeySharesAsync(
        IDbConnection connection, InsertMasterKeySharesEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@MembershipUniqueId", cmd.MembershipUniqueId);

        DataTable sharesTable = new();
        sharesTable.Columns.Add("ShareIndex", typeof(int));
        sharesTable.Columns.Add("EncryptedShare", typeof(byte[]));
        sharesTable.Columns.Add("ShareMetadata", typeof(string));
        sharesTable.Columns.Add("StorageLocation", typeof(string));

        foreach (ShareData share in cmd.Shares)
        {
            sharesTable.Rows.Add(share.ShareIndex, share.EncryptedShare, share.ShareMetadata, share.StorageLocation);
        }

        parameters.Add("@Shares", sharesTable.AsTableValuedParameter("dbo.MasterKeyShareTableType"));

        InsertMasterKeySharesResult? result = await connection.QuerySingleOrDefaultAsync<InsertMasterKeySharesResult>(
            "dbo.InsertMasterKeyShares",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        if (result is null)
        {
            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed("Insert master key shares failed - stored procedure returned null result"));
        }

        if (!result.Success)
        {
            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed($"Insert failed: {result.Message}"));
        }

        return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Ok(result);
    }

    private static async Task<Result<IReadOnlyList<MasterKeyShareQueryRecord>, KeySplittingFailure>> GetMasterKeySharesByMembershipIdAsync(
        IDbConnection connection, GetMasterKeySharesEvent cmd)
    {
        DynamicParameters parameters = new();
        parameters.Add("@MembershipUniqueId", cmd.MembershipUniqueId);

        IEnumerable<MasterKeyShareQueryRecord> shares = await connection.QueryAsync<MasterKeyShareQueryRecord>(
            "dbo.GetMasterKeySharesByMembership",
            parameters,
            commandType: CommandType.StoredProcedure
        );

        List<MasterKeyShareQueryRecord> sharesList = shares.ToList();

        if (sharesList.Count == 0)
        {
            return Result<IReadOnlyList<MasterKeyShareQueryRecord>, KeySplittingFailure>.Err(
                KeySplittingFailure.InsufficientShares(0, 1));
        }

        return Result<IReadOnlyList<MasterKeyShareQueryRecord>, KeySplittingFailure>.Ok(sharesList);
    }

    protected override KeySplittingFailure MapDbException(DbException ex)
    {
        Log.Error(ex, "Database exception in {ActorType}: {ExceptionType} - {Message}",
            GetType().Name, ex.GetType().Name, ex.Message);

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
        Log.Error(ex, "Timeout exception in {ActorType}: Operation timed out", GetType().Name);
        return KeySplittingFailure.KeySplittingFailed("Database operation timed out", ex);
    }

    protected override KeySplittingFailure CreateGenericFailure(Exception ex)
    {
        Log.Error(ex, "Generic exception in {ActorType}: {ExceptionType} - {Message}",
            GetType().Name, ex.GetType().Name, ex.Message);
        return KeySplittingFailure.KeySplittingFailed($"Unexpected error in master key share persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
