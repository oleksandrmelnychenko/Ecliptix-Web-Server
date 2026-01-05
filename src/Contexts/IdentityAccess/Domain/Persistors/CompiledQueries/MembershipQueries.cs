using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.IdentityAccess.Domain.Memberships.Persistors.CompiledQueries;

public static class MembershipQueries
{
    private static readonly Func<EcliptixSchemaContext, string, Task<MembershipEntity?>>
        GetByMobileNumberCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber) =>
                ctx.Memberships
                    .Join(ctx.MobileNumbers,
                        m => m.MobileNumberId,
                        mn => mn.UniqueId,
                        (m, mn) => new { m, mn })
                    .Where(x => x.mn.Number == mobileNumber &&
                                !x.m.IsDeleted &&
                                !x.mn.IsDeleted)
                    .Select(x => x.m)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<MembershipEntity>> GetByMobileNumber(
        EcliptixSchemaContext ctx,
        string mobileNumber,
        CancellationToken cancellationToken = default)
    {
        MembershipEntity? result = await GetByMobileNumberCompiled(ctx, mobileNumber);
        return result is not null ? Option<MembershipEntity>.Some(result) : Option<MembershipEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<MembershipEntity?>>
        GetByMobileUniqueIdAndDeviceCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, Guid deviceId) =>
                ctx.Memberships
                    .AsNoTracking()
                    .FirstOrDefault(m => m.MobileNumberId == mobileUniqueId &&
                                        m.AppDeviceId == deviceId &&
                                        !m.IsDeleted));

    public static async Task<Option<MembershipEntity>> GetByMobileUniqueIdAndDevice(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        MembershipEntity? result = await GetByMobileUniqueIdAndDeviceCompiled(ctx, mobileUniqueId, deviceId);
        return result is not null ? Option<MembershipEntity>.Some(result) : Option<MembershipEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Task<MembershipEntity?>>
        GetByUniqueIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.Memberships
                    .AsNoTracking()
                    .FirstOrDefault(m => m.UniqueId == uniqueId && !m.IsDeleted));

    public static async Task<Option<MembershipEntity>> GetByUniqueId(
        EcliptixSchemaContext ctx,
        Guid uniqueId,
        CancellationToken cancellationToken = default)
    {
        MembershipEntity? result = await GetByUniqueIdCompiled(ctx, uniqueId);
        return result is not null ? Option<MembershipEntity>.Some(result) : Option<MembershipEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Task<MembershipEntity?>>
        GetByMobileUniqueIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId) =>
                ctx.Memberships
                    .Include(m => m.MobileNumber)
                    .AsNoTracking()
                    .Where(m => m.MobileNumber.UniqueId == mobileUniqueId &&
                                !m.IsDeleted &&
                                !m.MobileNumber.IsDeleted)
                    .OrderByDescending(m => m.UpdatedAt)
                    .FirstOrDefault());

    public static async Task<Option<MembershipEntity>> GetByMobileUniqueId(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        CancellationToken cancellationToken = default)
    {
        MembershipEntity? result = await GetByMobileUniqueIdCompiled(ctx, mobileUniqueId);
        return result is not null ? Option<MembershipEntity>.Some(result) : Option<MembershipEntity>.None;
    }
}
