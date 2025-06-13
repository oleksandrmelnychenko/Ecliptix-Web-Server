using System.Data;

namespace Ecliptix.Domain.DbConnectionFactory;

public interface IDbConnectionFactory
{
    Task<IDbConnection> CreateOpenConnectionAsync(CancellationToken cancellationToken = default);
}