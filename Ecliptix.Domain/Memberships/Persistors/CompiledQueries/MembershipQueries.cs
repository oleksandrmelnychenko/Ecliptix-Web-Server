using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MembershipQueries
{
    public static async Task<MembershipEntity?> GetByMobileNumber(
        EcliptixSchemaContext ctx,
        string mobileNumber,
        CancellationToken cancellationToken = default)
    {
        return await ctx.Memberships
            .Join(ctx.MobileNumbers,
                m => m.MobileNumberId,
                mn => mn.UniqueId,
                (m, mn) => new { m, mn })
            .Where(x => x.mn.Number == mobileNumber &&
                        !x.m.IsDeleted &&
                        !x.mn.IsDeleted)
            .Select(x => x.m)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<MembershipEntity?> GetByMobileUniqueIdAndDevice(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.Memberships
            .Where(m => m.MobileNumberId == mobileUniqueId &&
                        m.AppDeviceId == deviceId &&
                        !m.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<MembershipEntity?> GetByUniqueId(
        EcliptixSchemaContext ctx,
        Guid uniqueId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.Memberships
            .Where(m => m.UniqueId == uniqueId && !m.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<MembershipEntity?> GetByMobileUniqueId(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.Memberships
            .Include(m => m.MobileNumber)
            .Include(m => m.VerificationFlow)
            .Where(m => m.MobileNumber!.UniqueId == mobileUniqueId &&
                        !m.IsDeleted &&
                        !m.MobileNumber.IsDeleted)
            .OrderByDescending(m => m.UpdatedAt)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<bool> ExistsByMobileNumberId(
        EcliptixSchemaContext ctx,
        Guid mobileNumberId,
        CancellationToken cancellationToken = default)
    {
        return await ctx.Memberships
            .AnyAsync(m => m.MobileNumberId == mobileNumberId && !m.IsDeleted, cancellationToken);
    }
}
