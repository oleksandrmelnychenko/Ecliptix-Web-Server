using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

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
                    .Where(vf => vf.MobileNumberId == mobileUniqueId &&
                                vf.AppDeviceId == deviceId &&
                                vf.Purpose == purpose &&
                                vf.Status == "pending" &&
                                vf.ExpiresAt > DateTimeOffset.UtcNow &&
                                !vf.IsDeleted)
                    .AsNoTracking()
                    .Any());

    public static readonly Func<EcliptixSchemaContext, Guid, Guid, string, Task<VerificationFlowEntity?>>
        GetActiveFlowForRecovery = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, Guid deviceId, string purpose) =>
                ctx.VerificationFlows
                    .Where(vf => vf.MobileNumberId == mobileUniqueId &&
                                vf.AppDeviceId == deviceId &&
                                vf.Purpose == purpose &&
                                vf.Status == "pending" &&
                                vf.ExpiresAt > DateTimeOffset.UtcNow &&
                                !vf.IsDeleted)
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, DateTimeOffset, Task<int>>
        CountRecentByMobileId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, DateTimeOffset since) =>
                ctx.VerificationFlows
                    .Where(f => f.MobileNumberId == mobileUniqueId &&
                                f.CreatedAt > since &&
                                !f.IsDeleted)
                    .AsNoTracking()
                    .Count());

    public static readonly Func<EcliptixSchemaContext, Guid, DateTimeOffset, Task<int>>
        CountRecentByDevice = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid deviceId, DateTimeOffset since) =>
                ctx.VerificationFlows
                    .Where(f => f.AppDeviceId == deviceId &&
                                f.CreatedAt > since &&
                                !f.IsDeleted)
                    .AsNoTracking()
                    .Count());

    public static readonly Func<EcliptixSchemaContext, Guid, DateTimeOffset, Task<int>>
        CountRecentPasswordRecovery = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid mobileUniqueId, DateTimeOffset since) =>
                ctx.VerificationFlows
                    .Where(f => f.MobileNumberId == mobileUniqueId &&
                                f.Purpose == "password_recovery" &&
                                f.CreatedAt >= since &&
                                !f.IsDeleted)
                    .AsNoTracking()
                    .Count());
}
