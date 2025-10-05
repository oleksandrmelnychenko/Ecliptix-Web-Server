using Microsoft.EntityFrameworkCore;
using Ecliptix.Memberships.Persistor.Schema;
using Ecliptix.Memberships.Persistor.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class MembershipQueries
{
    /// <summary>
    /// Get membership by mobile number (for login)
    /// Filters by mobile number string via join
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, string, Task<Membership?>>
        GetByMobileNumber = EF.CompileAsyncQuery(
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

    /// <summary>
    /// Get membership by mobile UniqueId and device UniqueId
    /// Used for duplicate check in CreateMembership
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<Membership?>>
        GetByMobileUniqueIdAndDevice = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, Guid deviceId) =>
                ctx.Memberships
                    .Where(m => m.MobileNumberId == mobileUniqueId &&
                                m.AppDeviceId == deviceId &&
                                !m.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    /// <summary>
    /// Get membership by UniqueId
    /// </summary>
    public static readonly Func<EcliptixSchemaContext, Guid, Task<Membership?>>
        GetByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid uniqueId) =>
                ctx.Memberships
                    .Where(m => m.UniqueId == uniqueId && !m.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());
}
