using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class VerificationFlowQueries
{
    public static readonly Func<EcliptixSchemaContext, Guid, Task<VerificationFlow?>>
        GetByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid flowId) =>
                ctx.VerificationFlows
                    .Where(f => f.UniqueId == flowId && !f.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<VerificationFlow?>>
        GetByUniqueIdWithMobile = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid flowId) =>
                ctx.VerificationFlows
                    .Where(f => f.UniqueId == flowId && !f.IsDeleted)
                    .Include(f => f.MobileNumber)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<VerificationFlow?>>
        GetByUniqueIdWithActiveOtp = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid flowId) =>
                ctx.VerificationFlows
                    .Where(f => f.UniqueId == flowId && !f.IsDeleted)
                    .Include(f => f.MobileNumber)
                    .Include(f => f.OtpCodes.Where(o => o.Status == "active" && !o.IsDeleted))
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, long, Task<VerificationFlow?>>
        GetByUniqueIdAndConnectionId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid flowId, long connectionId) =>
                ctx.VerificationFlows
                    .Where(f => f.UniqueId == flowId &&
                                f.ConnectionId == connectionId &&
                                f.Purpose == "registration" &&
                                !f.IsDeleted)
                    .Include(f => f.MobileNumber)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Guid, string, Task<bool>>
        HasActiveFlow = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, Guid deviceId, string purpose) =>
                ctx.VerificationFlows
                    .Join(ctx.MobileNumbers,
                        vf => vf.MobileNumberId,
                        mn => mn.Id,
                        (vf, mn) => new { vf, mn })
                    .Where(x => x.mn.UniqueId == mobileUniqueId &&
                                x.vf.AppDeviceId == deviceId &&
                                x.vf.Purpose == purpose &&
                                x.vf.Status == "pending" &&
                                x.vf.ExpiresAt > DateTime.UtcNow &&
                                !x.vf.IsDeleted)
                    .AsNoTracking()
                    .Any());

    public static readonly Func<EcliptixSchemaContext, Guid, Guid, string, Task<VerificationFlow?>>
        GetActiveFlowForRecovery = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, Guid deviceId, string purpose) =>
                ctx.VerificationFlows
                    .Join(ctx.MobileNumbers,
                        vf => vf.MobileNumberId,
                        mn => mn.Id,
                        (vf, mn) => new { vf, mn })
                    .Where(x => x.mn.UniqueId == mobileUniqueId &&
                                x.vf.AppDeviceId == deviceId &&
                                x.vf.Purpose == purpose &&
                                x.vf.Status == "pending" &&
                                x.vf.ExpiresAt > DateTime.UtcNow &&
                                !x.vf.IsDeleted)
                    .Select(x => x.vf)
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, long, DateTime, Task<int>>
        CountRecentByMobileId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, long mobileId, DateTime since) =>
                ctx.VerificationFlows
                    .Where(f => f.MobileNumberId == mobileId &&
                                f.CreatedAt > since &&
                                !f.IsDeleted)
                    .AsNoTracking()
                    .Count());

    public static readonly Func<EcliptixSchemaContext, Guid, DateTime, Task<int>>
        CountRecentByDevice = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid deviceId, DateTime since) =>
                ctx.VerificationFlows
                    .Where(f => f.AppDeviceId == deviceId &&
                                f.CreatedAt > since &&
                                !f.IsDeleted)
                    .AsNoTracking()
                    .Count());

    public static readonly Func<EcliptixSchemaContext, long, DateTime, Task<int>>
        CountRecentPasswordRecovery = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, long mobileId, DateTime since) =>
                ctx.VerificationFlows
                    .Where(f => f.MobileNumberId == mobileId &&
                                f.Purpose == "password_recovery" &&
                                f.CreatedAt >= since &&
                                !f.IsDeleted)
                    .AsNoTracking()
                    .Count());
}
