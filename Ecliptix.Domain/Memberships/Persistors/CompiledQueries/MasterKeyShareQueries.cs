using System.Threading;
using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MasterKeyShareQueries
{
    public static async Task<List<MasterKeyShareEntity>> GetByMembershipUniqueId(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid membershipUniqueId,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.MasterKeyShares
            .Where(s => s.MembershipUniqueId == membershipUniqueId && !s.IsDeleted)
            .OrderBy(s => s.ShareIndex)
            .AsNoTracking()
            .ToListAsync(cancellationToken);
    }
}
