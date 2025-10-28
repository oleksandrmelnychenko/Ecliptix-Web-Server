using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MembershipQueries
{
    public static async Task<Option<MembershipEntity>> GetByMobileNumber(
        EcliptixSchemaContext ctx,
        string mobileNumber,
        CancellationToken cancellationToken = default)
    {
        MembershipEntity? result = await ctx.Memberships
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

        return result is not null ? Option<MembershipEntity>.Some(result) : Option<MembershipEntity>.None;
    }

    public static async Task<Option<MembershipEntity>> GetByMobileUniqueIdAndDevice(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        MembershipEntity? result = await ctx.Memberships
            .Where(m => m.MobileNumberId == mobileUniqueId &&
                        m.AppDeviceId == deviceId &&
                        !m.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<MembershipEntity>.Some(result) : Option<MembershipEntity>.None;
    }

    public static async Task<Option<MembershipEntity>> GetByUniqueId(
        EcliptixSchemaContext ctx,
        Guid uniqueId,
        CancellationToken cancellationToken = default)
    {
        MembershipEntity? result = await ctx.Memberships
            .Where(m => m.UniqueId == uniqueId && !m.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<MembershipEntity>.Some(result) : Option<MembershipEntity>.None;
    }

    public static async Task<Option<MembershipEntity>> GetByMobileUniqueId(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        CancellationToken cancellationToken = default)
    {
        MembershipEntity? result = await ctx.Memberships
            .Include(m => m.MobileNumber)
            .Where(m => m.MobileNumber!.UniqueId == mobileUniqueId &&
                        !m.IsDeleted &&
                        !m.MobileNumber.IsDeleted)
            .OrderByDescending(m => m.UpdatedAt)
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<MembershipEntity>.Some(result) : Option<MembershipEntity>.None;
    }
}
