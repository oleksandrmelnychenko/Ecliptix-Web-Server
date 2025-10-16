using System.Threading;
using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Domain.Memberships;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class VerificationFlowQueries
{
    public static async Task<VerificationFlowEntity?> GetByUniqueId(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid flowId,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.VerificationFlows
            .Where(f => f.UniqueId == flowId && !f.IsDeleted)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<VerificationFlowEntity?> GetByUniqueIdWithMobile(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid flowId,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.VerificationFlows
            .Where(f => f.UniqueId == flowId && !f.IsDeleted)
            .Include(f => f.MobileNumber)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<VerificationFlowEntity?> GetByUniqueIdWithActiveOtp(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid flowId,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.VerificationFlows
            .Where(f => f.UniqueId == flowId && !f.IsDeleted)
            .Include(f => f.MobileNumber)
            .Include(f => f.OtpCodes.Where(o => o.Status == VerificationFlowDbValues.OtpStatusActive && !o.IsDeleted))
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<VerificationFlowEntity?> GetByUniqueIdAndConnectionId(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid flowId,
        long connectionId,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.VerificationFlows
            .Where(f => f.UniqueId == flowId &&
                        f.ConnectionId == connectionId &&
                        f.Purpose == VerificationFlowDbValues.PurposeRegistration &&
                        !f.IsDeleted)
            .Include(f => f.MobileNumber)
            .AsNoTracking()
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<bool> HasActiveFlow(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid mobileUniqueId,
        Guid deviceId,
        string purpose,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.VerificationFlows
            .Where(vf => vf.MobileNumberId == mobileUniqueId &&
                        vf.AppDeviceId == deviceId &&
                        vf.Purpose == purpose &&
                        vf.Status == VerificationFlowDbValues.StatusPending &&
                        vf.ExpiresAt > DateTimeOffset.UtcNow &&
                        !vf.IsDeleted)
            .AsNoTracking()
            .AnyAsync(cancellationToken);
    }

    public static async Task<VerificationFlowEntity?> GetActiveFlowForRecovery(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid mobileUniqueId,
        Guid deviceId,
        string purpose,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.VerificationFlows
            .Where(vf => vf.MobileNumberId == mobileUniqueId &&
                        vf.AppDeviceId == deviceId &&
                        vf.Purpose == purpose &&
                        vf.Status == VerificationFlowDbValues.StatusPending &&
                        vf.ExpiresAt > DateTimeOffset.UtcNow &&
                        !vf.IsDeleted)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public static async Task<int> CountRecentByMobileId(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid mobileUniqueId,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.VerificationFlows
            .Where(f => f.MobileNumberId == mobileUniqueId &&
                        f.CreatedAt > since &&
                        !f.IsDeleted)
            .AsNoTracking()
            .CountAsync(cancellationToken);
    }

    public static async Task<int> CountRecentByDevice(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid deviceId,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.VerificationFlows
            .Where(f => f.AppDeviceId == deviceId &&
                        f.CreatedAt > since &&
                        !f.IsDeleted)
            .AsNoTracking()
            .CountAsync(cancellationToken);
    }

    public static async Task<int> CountRecentPasswordRecovery(
        EcliptixSchemaContext ecliptixSchemaContext,
        Guid mobileUniqueId,
        DateTimeOffset since,
        CancellationToken cancellationToken = default)
    {
        return await ecliptixSchemaContext.VerificationFlows
            .Where(f => f.MobileNumberId == mobileUniqueId &&
                        f.Purpose == VerificationFlowDbValues.PurposePasswordRecovery &&
                        f.CreatedAt >= since &&
                        !f.IsDeleted)
            .AsNoTracking()
            .CountAsync(cancellationToken);
    }
}
