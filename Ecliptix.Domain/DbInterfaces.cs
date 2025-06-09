using System.Data;
using System.Data.Common;

namespace Ecliptix.Domain;

public interface IDbDataSource
{
    Task<IDbConnection> CreateConnection(CancellationToken cancellationToken = default);
}

public interface IDbConnection : IAsyncDisposable
{
    Task OpenAsync(CancellationToken cancellationToken = default);
    IDbCommand CreateCommand();
    string Host { get; }
}

public interface IDbCommand : IAsyncDisposable
{
    string CommandText { get; set; }
    DbParameterCollection Parameters { get; }
    IDbDataReader ExecuteReader(CancellationToken cancellationToken = default);
    Task<IDbDataReader> ExecuteReaderAsync(CancellationToken cancellationToken = default);
    Task<int> ExecuteNonQueryAsync(CancellationToken cancellationToken = default);
}

public interface IDbDataReader : IAsyncDisposable
{
    Task<bool> ReadAsync(CancellationToken cancellationToken = default);
    bool IsDBNull(int ordinal);
    bool GetBoolean(int ordinal);
    short GetInt16(int ordinal);
    int GetInt32(int ordinal);
    long GetInt64(int ordinal);
    Guid GetGuid(int ordinal);
    string GetString(int ordinal);
    DateTime GetDateTime(int ordinal);
    
    T GetFieldValue<T>(int ordinal);
}
