using System.Threading;
using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class VerificationFlowQueries
{
    public static async Task<Option<VerificationFlowEntity>> GetByUniqueId(
        EcliptixSchemaContext ctx,
        Guid flowId,
        CancellationToken cancellationToken = default)
    {
        VerificationFlowEntity? result = await ctx.VerificationFlows
            .Where(f => f.UniqueId == flowId && !f.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<VerificationFlowEntity>.Some(result) : Option<VerificationFlowEntity>.None;
    }

    public static async Task<Option<VerificationFlowEntity>> GetByUniqueIdWithMobile(
        EcliptixSchemaContext ctx,
        Guid flowId,
        CancellationToken cancellationToken = default)
    {
        VerificationFlowEntity? result = await ctx.VerificationFlows
            .Where(f => f.UniqueId == flowId && !f.IsDeleted)
            .Include(f => f.MobileNumber)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<VerificationFlowEntity>.Some(result) : Option<VerificationFlowEntity>.None;
    }

    public static async Task<Option<VerificationFlowEntity>> GetByUniqueIdWithActiveOtp(
        EcliptixSchemaContext ctx,
        Guid flowId,
        CancellationToken cancellationToken = default)
    {
        VerificationFlowEntity? result = await ctx.VerificationFlows
            .Where(f => f.UniqueId == flowId && !f.IsDeleted)
            .Include(f => f.MobileNumber)
            .Include(f => f.OtpCodes.Where(o => o.Status == "active" && !o.IsDeleted))
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<VerificationFlowEntity>.Some(result) : Option<VerificationFlowEntity>.None;
    }

    public static async Task<Option<VerificationFlowEntity>> GetByUniqueIdAndConnectionId(
        EcliptixSchemaContext ctx,
        Guid flowId,
        long connectionId,
        CancellationToken cancellationToken = default)
    {
        VerificationFlowEntity? result = await ctx.VerificationFlows
            .Where(f => f.UniqueId == flowId &&
                        f.ConnectionId == connectionId &&
                        f.Purpose == "registration" &&
                        !f.IsDeleted)
            .Include(f => f.MobileNumber)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<VerificationFlowEntity>.Some(result) : Option<VerificationFlowEntity>.None;
    }

    public static async Task<bool> HasActiveFlow(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        Guid deviceId,
        string purpose,
        CancellationToken cancellationToken = default)
    {
        return await ctx.VerificationFlows
            .Where(vf => vf.MobileNumberId == mobileUniqueId &&
                        vf.AppDeviceId == deviceId &&
                        vf.Purpose == purpose &&
                        vf.Status == "pending" &&
                        vf.ExpiresAt > DateTimeOffset.UtcNow &&
                        !vf.IsDeleted)
            .AsNoTracking()
            .AnyAsync(cancellationToken);
    }

    public static async Task<Option<VerificationFlowEntity>> GetActiveFlowForRecovery(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        Guid deviceId,
        string purpose,
        CancellationToken cancellationToken = default)
    {
        VerificationFlowEntity? result = await ctx.VerificationFlows
            .Where(vf => vf.MobileNumberId == mobileUniqueId &&
                        vf.AppDeviceId == deviceId &&
                        vf.Purpose == purpose &&
                        vf.Status == "pending" &&
                        vf.ExpiresAt > DateTimeOffset.UtcNow &&
                        !vf.IsDeleted)
            .FirstOrDefaultAsync(cancellationToken);

        return result is not null ? Option<VerificationFlowEntity>.Some(result) : Option<VerificationFlowEntity>.None;
    }

    public static async Task<int> CountRecentByMobileId(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return await ctx.VerificationFlows
            .Where(f => f.MobileNumberId == mobileUniqueId &&
                        f.CreatedAt > since &&
                        !f.IsDeleted)
            .AsNoTracking()
            .CountAsync(cancellationToken);
    }

    public static async Task<int> CountRecentByDevice(
        EcliptixSchemaContext ctx,
        Guid deviceId,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return await ctx.VerificationFlows
            .Where(f => f.AppDeviceId == deviceId &&
                        f.CreatedAt > since &&
                        !f.IsDeleted)
            .AsNoTracking()
            .CountAsync(cancellationToken);
    }

    public static async Task<int> CountRecentPasswordRecovery(
        EcliptixSchemaContext ctx,
        Guid mobileUniqueId,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return await ctx.VerificationFlows
            .Where(f => f.MobileNumberId == mobileUniqueId &&
                        f.Purpose == "password_recovery" &&
                        f.CreatedAt >= since &&
                        !f.IsDeleted)
            .AsNoTracking()
            .CountAsync(cancellationToken);
    }
}
