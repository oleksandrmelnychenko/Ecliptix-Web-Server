using System.Data;
using System.Data.Common;
using Npgsql;

namespace Ecliptix.Domain;

public class NpgsqlDataSourceWrapper : IDbDataSource
{
    private readonly NpgsqlDataSource _dataSource;

    public NpgsqlDataSourceWrapper(NpgsqlDataSource dataSource) => _dataSource = dataSource;

    public async Task<IDbConnection> CreateConnection(CancellationToken cancellationToken = default) =>
        new NpgsqlConnectionWrapper(_dataSource.CreateConnection());
}

public class NpgsqlConnectionWrapper : IDbConnection
{
    private readonly NpgsqlConnection _connection;

    public NpgsqlConnectionWrapper(NpgsqlConnection connection) => _connection = connection;

    public Task OpenAsync(CancellationToken cancellationToken = default) => _connection.OpenAsync(cancellationToken);
    public IDbCommand CreateCommand() => new NpgsqlCommandWrapper(_connection.CreateCommand());
    public string Host { get; }
    public ValueTask DisposeAsync() => _connection.DisposeAsync();
}

public class NpgsqlCommandWrapper : IDbCommand
{
    private readonly NpgsqlCommand _command;

    public NpgsqlCommandWrapper(NpgsqlCommand command) => _command = command;

    public string CommandText
    {
        get => _command.CommandText;
        set => _command.CommandText = value;
    }

    public DbParameterCollection Parameters => _command.Parameters;

    public IDbDataReader ExecuteReader(CancellationToken cancellationToken = default) 
        => new NpgsqlDataReaderWrapper(_command.ExecuteReader());
    public async Task<IDbDataReader> ExecuteReaderAsync(CancellationToken cancellationToken = default) =>
        new NpgsqlDataReaderWrapper(await _command.ExecuteReaderAsync(cancellationToken));

    public async Task<int> ExecuteNonQueryAsync(CancellationToken cancellationToken = default)
    {
        return await _command.ExecuteNonQueryAsync(cancellationToken);
    }
    
    public ValueTask DisposeAsync() => _command.DisposeAsync();
}

public class NpgsqlDataReaderWrapper : IDbDataReader
{
    private readonly NpgsqlDataReader _reader;

    public NpgsqlDataReaderWrapper(NpgsqlDataReader reader) => _reader = reader;

    public Task<bool> ReadAsync(CancellationToken cancellationToken = default) => _reader.ReadAsync(cancellationToken);
    public bool IsDBNull(int ordinal) => _reader.IsDBNull(ordinal);
    public short GetInt16(int ordinal) => _reader.GetInt16(ordinal);
    public int GetInt32(int ordinal) => _reader.GetInt32(ordinal);
    public long GetInt64(int ordinal) => _reader.GetInt64(ordinal);
    public bool GetBoolean(int ordinal) => _reader.GetBoolean(ordinal);
    public Guid GetGuid(int ordinal) => _reader.GetGuid(ordinal);
    public string GetString(int ordinal) => _reader.GetString(ordinal);
    public DateTime GetDateTime(int ordinal) => _reader.GetDateTime(ordinal);
    public ValueTask DisposeAsync() => _reader.DisposeAsync();
    public T GetFieldValue<T>(int ordinal) => _reader.GetFieldValue<T>(ordinal);
}
