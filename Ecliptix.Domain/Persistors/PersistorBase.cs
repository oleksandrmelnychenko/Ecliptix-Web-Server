using Akka.Actor;
using Ecliptix.Domain.Utilities;
using Npgsql;

namespace Ecliptix.Domain.Persistors;

public abstract class PersistorBase(NpgsqlDataSource npgsqlDataSource) :ReceiveActor
{
    protected NpgsqlDataSource NpgsqlDataSource { get; } = npgsqlDataSource;

    protected async Task ExecuteWithConnection<T>(
        Func<NpgsqlConnection, Task<Result<T, ShieldFailure>>> operation,
        string operationName)
    {
        try
        {
            await using NpgsqlConnection conn = NpgsqlDataSource.CreateConnection();
            await conn.OpenAsync();
            Result<T, ShieldFailure> result = await operation(conn);
            Sender.Tell(result);
        }
        catch (NpgsqlException dbEx)
        {
            Sender.Tell(Result<T, ShieldFailure>.Err(
                ShieldFailure.DataAccess($"Database error during {operationName}: {dbEx.Message}", dbEx)));
        }
        catch (Exception ex)
        {
            Sender.Tell(Result<T, ShieldFailure>.Err(
                ShieldFailure.Generic($"Unexpected error during {operationName}: {ex.Message}", ex)));
        }
    }
    
    protected static NpgsqlCommand CreateCommand(NpgsqlConnection connection, string sql,
        params NpgsqlParameter[] parameters)
    {
        NpgsqlCommand command = new(sql, connection);
        command.Parameters.AddRange(parameters);
        return command;
    }
}