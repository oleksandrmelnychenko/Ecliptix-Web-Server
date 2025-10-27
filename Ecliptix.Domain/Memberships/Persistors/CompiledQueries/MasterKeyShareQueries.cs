using System.Threading;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MasterKeyShareQueries
{
    public static async Task<List<MasterKeyShareEntity>> GetByMembershipUniqueId(
        EcliptixSchemaContext ctx,
        Guid membershipUniqueId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.MasterKeyShares
            .Where(s => s.MembershipUniqueId == membershipUniqueId && !s.IsDeleted)
            .OrderBy(s => s.ShareIndex)
            .AsNoTracking()
            .ToListAsync(cancellationToken);
    }
}
