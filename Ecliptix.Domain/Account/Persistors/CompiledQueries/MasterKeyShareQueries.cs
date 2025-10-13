using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Account.Persistors.CompiledQueries;

public static class MasterKeyShareQueries
{
    public static async Task<List<MasterKeyShareEntity>> GetByAccountUniqueId(
        EcliptixSchemaContext ctx,
        Guid accountUniqueId)
    {
        return await ctx.MasterKeyShares
            .Where(s => s.AccountUniqueId == accountUniqueId && !s.IsDeleted)
            .OrderBy(s => s.ShareIndex)
            .AsNoTracking()
            .ToListAsync();
    }
}
