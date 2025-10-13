using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Account.Persistors.CompiledQueries;

public static class VerificationFlowQueries
{
    public static readonly Func<EcliptixSchemaContext, Guid, Task<VerificationFlowEntity?>>
        GetByUniqueId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid flowId) =>
                ctx.VerificationFlows
                    .Where(f => f.UniqueId == flowId && !f.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<VerificationFlowEntity?>>
        GetByUniqueIdWithMobile = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid flowId) =>
                ctx.VerificationFlows
                    .Where(f => f.UniqueId == flowId && !f.IsDeleted)
                    .Include(f => f.MobileNumber)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<VerificationFlowEntity?>>
        GetByUniqueIdWithActiveOtp = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid flowId) =>
                ctx.VerificationFlows
                    .Where(f => f.UniqueId == flowId && !f.IsDeleted)
                    .Include(f => f.MobileNumber)
                    .Include(f => f.OtpCodes.Where(o => o.Status == "active" && !o.IsDeleted))
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, long, Task<VerificationFlowEntity?>>
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
                        mn => mn.UniqueId,
                        (vf, mn) => new { vf, mn })
                    .Join(ctx.Devices,
                        x => x.vf.AppDeviceId,
                        d => d.UniqueId,
                        (x, d) => new { x.vf, x.mn, d })
                    .Where(x => x.mn.UniqueId == mobileUniqueId &&
                                x.d.DeviceId == deviceId &&
                                x.vf.Purpose == purpose &&
                                x.vf.Status == "pending" &&
                                x.vf.ExpiresAt > DateTime.UtcNow &&
                                !x.vf.IsDeleted &&
                                !x.mn.IsDeleted &&
                                !x.d.IsDeleted)
                    .AsNoTracking()
                    .Any());

public static readonly Func<EcliptixSchemaContext, Guid, Guid, string, Task<VerificationFlowEntity?>>
        GetActiveFlowForRecovery = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, Guid deviceId, string purpose) =>
                ctx.VerificationFlows
                    .Join(ctx.MobileNumbers,
                        vf => vf.MobileNumberId,
                        mn => mn.UniqueId,
                        (vf, mn) => new { vf, mn })
                    .Join(ctx.Devices,
                        x => x.vf.AppDeviceId,
                        d => d.UniqueId,
                        (x, d) => new { x.vf, x.mn, d })
                    .Where(x => x.mn.UniqueId == mobileUniqueId &&
                                x.d.DeviceId == deviceId &&
                                x.vf.Purpose == purpose &&
                                x.vf.Status == "pending" &&
                                x.vf.ExpiresAt > DateTime.UtcNow &&
                                !x.vf.IsDeleted &&
                                !x.mn.IsDeleted &&
                                !x.d.IsDeleted)
                    .Select(x => x.vf)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, DateTime, Task<int>>
        CountRecentByMobileId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileId, DateTime since) =>
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

    public static readonly Func<EcliptixSchemaContext, Guid, DateTime, Task<int>>
        CountRecentPasswordRecovery = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileId, DateTime since) =>
                ctx.VerificationFlows
                    .Where(f => f.MobileNumberId == mobileId &&
                                f.Purpose == "password_recovery" &&
                                f.CreatedAt >= since &&
                                !f.IsDeleted)
                    .AsNoTracking()
                    .Count());
}
