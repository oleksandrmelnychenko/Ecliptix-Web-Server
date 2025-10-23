using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class AccountSecureKeyAuthQueries
{
    /// <summary>
    /// Get the primary AccountSecureKeyAuth for a specific account
    /// </summary>
    private static readonly Func<EcliptixSchemaContext, Guid, Task<AccountSecureKeyAuthEntity?>>
        GetPrimaryForAccountCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid accountId) =>
                ctx.AccountSecureKeyAuths
                    .Where(a => a.AccountId == accountId &&
                                a.IsPrimary &&
                                a.IsEnabled &&
                                !a.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<AccountSecureKeyAuthEntity>> GetPrimaryForAccount(
        EcliptixSchemaContext ctx,
        Guid accountId)
    {
        AccountSecureKeyAuthEntity? result = await GetPrimaryForAccountCompiled(ctx, accountId);
        return result is not null
            ? Option<AccountSecureKeyAuthEntity>.Some(result)
            : Option<AccountSecureKeyAuthEntity>.None;
    }

    /// <summary>
    /// Get the primary AccountSecureKeyAuth for the default account of a membership
    /// OPTIMIZED: Single query with JOIN instead of 2 sequential queries
    /// </summary>
    private static readonly Func<EcliptixSchemaContext, Guid, Task<AccountSecureKeyAuthEntity?>>
        GetPrimaryForMembershipCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId) =>
                ctx.AccountSecureKeyAuths
                    .Where(auth => auth.Account.MembershipId == membershipId &&
                                  auth.Account.IsDefaultAccount &&
                                  auth.IsPrimary &&
                                  auth.IsEnabled &&
                                  !auth.IsDeleted &&
                                  !auth.Account.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<AccountSecureKeyAuthEntity>> GetPrimaryForMembership(
        EcliptixSchemaContext ctx,
        Guid membershipId)
    {
        AccountSecureKeyAuthEntity? result = await GetPrimaryForMembershipCompiled(ctx, membershipId);
        return result is not null
            ? Option<AccountSecureKeyAuthEntity>.Some(result)
            : Option<AccountSecureKeyAuthEntity>.None;
    }

    /// <summary>
    /// Get the primary AccountSecureKeyAuth for the active account on a specific device
    /// OPTIMIZED: Single query with conditional logic, falls back to default account
    /// </summary>
    private static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<AccountSecureKeyAuthEntity?>>
        GetPrimaryForActiveAccountCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId, Guid deviceId) =>
                ctx.AccountSecureKeyAuths
                    .Where(auth =>
                        // Try to get auth for active account on device
                        (ctx.DeviceContexts
                            .Where(dc => dc.MembershipId == membershipId &&
                                        dc.DeviceId == deviceId &&
                                        dc.ActiveAccountId.HasValue &&
                                        !dc.IsDeleted)
                            .Select(dc => dc.ActiveAccountId)
                            .FirstOrDefault() == auth.AccountId
                        ||
                        // Fallback: get auth for default account
                        (ctx.Accounts
                            .Where(a => a.MembershipId == membershipId &&
                                       a.IsDefaultAccount &&
                                       !a.IsDeleted)
                            .Select(a => a.UniqueId)
                            .FirstOrDefault() == auth.AccountId))
                        &&
                        auth.IsPrimary &&
                        auth.IsEnabled &&
                        !auth.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<AccountSecureKeyAuthEntity>> GetPrimaryForActiveAccount(
        EcliptixSchemaContext ctx,
        Guid membershipId,
        Guid deviceId)
    {
        AccountSecureKeyAuthEntity? result = await GetPrimaryForActiveAccountCompiled(ctx, membershipId, deviceId);
        return result is not null
            ? Option<AccountSecureKeyAuthEntity>.Some(result)
            : Option<AccountSecureKeyAuthEntity>.None;
    }

    /// <summary>
    /// Get credentials tuple (SecureKey, MaskingKey, Version) for an account
    /// </summary>
    public static async Task<(byte[] SecureKey, byte[] MaskingKey, int Version)?> GetCredentialsForAccount(
        EcliptixSchemaContext ctx,
        Guid accountId)
    {
        Option<AccountSecureKeyAuthEntity> authOpt = await GetPrimaryForAccount(ctx, accountId);

        if (!authOpt.HasValue)
        {
            return null;
        }

        AccountSecureKeyAuthEntity auth = authOpt.Value;
        return (auth.SecureKey, auth.MaskingKey, auth.CredentialsVersion);
    }

    /// <summary>
    /// Get credentials for the default account of a membership
    /// OPTIMIZED: Single query instead of chaining queries
    /// </summary>
    private static readonly Func<EcliptixSchemaContext, Guid, Task<AccountSecureKeyAuthEntity?>>
        GetCredentialsForMembershipCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId) =>
                ctx.AccountSecureKeyAuths
                    .Where(auth => auth.Account.MembershipId == membershipId &&
                                  auth.Account.IsDefaultAccount &&
                                  auth.IsPrimary &&
                                  auth.IsEnabled &&
                                  !auth.IsDeleted &&
                                  !auth.Account.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<(byte[] SecureKey, byte[] MaskingKey, int Version)?> GetCredentialsForMembership(
        EcliptixSchemaContext ctx,
        Guid membershipId)
    {
        AccountSecureKeyAuthEntity? auth = await GetCredentialsForMembershipCompiled(ctx, membershipId);
        return auth != null ? (auth.SecureKey, auth.MaskingKey, auth.CredentialsVersion) : null;
    }
}
