using Microsoft.EntityFrameworkCore;
using Ecliptix.Memberships.Persistor.Schema;
using Ecliptix.Memberships.Persistor.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MasterKeyShareQueries
{
    /// <summary>
    /// Get all master key shares by membership UniqueId
    /// Returns ordered list for proper reconstruction
    /// Note: Not using EF.CompileAsyncQuery because it doesn't support ToListAsync
    /// </summary>
    public static async Task<List<MasterKeyShare>> GetByMembershipUniqueId(
        EcliptixSchemaContext ctx,
        Guid membershipUniqueId)
    {
        return await ctx.MasterKeyShares
            .Where(s => s.MembershipUniqueId == membershipUniqueId && !s.IsDeleted)
            .OrderBy(s => s.ShareIndex)
            .AsNoTracking()
            .ToListAsync();
    }
}
