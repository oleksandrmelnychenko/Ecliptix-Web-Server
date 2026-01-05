using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.IdentityAccess.Domain.Memberships.Persistors.CompiledQueries;

public static class MasterKeyShareQueries
{
    public static async Task<List<MasterKeyShareEntity>> GetByAccountUniqueId(
        EcliptixSchemaContext ctx,
        Guid accountUniqueId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.MasterKeyShares
            .Where(s => s.AccountUniqueId == accountUniqueId && !s.IsDeleted)
            .OrderBy(s => s.ShareIndex)
            .AsNoTracking()
            .ToListAsync(cancellationToken);
    }
}
