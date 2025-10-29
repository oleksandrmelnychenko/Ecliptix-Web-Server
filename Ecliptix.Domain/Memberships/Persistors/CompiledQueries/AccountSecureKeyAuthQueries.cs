using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public record CredentialsRecord(byte[] SecureKey, byte[] MaskingKey, int Version);

public static class AccountSecureKeyAuthQueries
{
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

    private static readonly Func<EcliptixSchemaContext, Guid, Guid, Task<AccountSecureKeyAuthEntity?>>
        GetPrimaryForActiveAccountCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId, Guid deviceId) =>
                ctx.AccountSecureKeyAuths
                    .Where(auth =>
                        (ctx.DeviceContexts
                            .Where(dc => dc.MembershipId == membershipId &&
                                        dc.DeviceId == deviceId &&
                                        dc.ActiveAccountId.HasValue &&
                                        dc.IsActive &&
                                        !dc.IsDeleted)
                            .Select(dc => dc.ActiveAccountId)
                            .FirstOrDefault() == auth.AccountId
                        ||
                        ctx.Accounts
                            .Where(a => a.MembershipId == membershipId &&
                                        a.IsDefaultAccount &&
                                        !a.IsDeleted)
                            .Select(a => a.UniqueId)
                            .FirstOrDefault() == auth.AccountId)
                        &&
                        auth.IsPrimary &&
                        auth.IsEnabled &&
                        !auth.IsDeleted &&
                        !auth.Account.IsDeleted)
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

    public static async Task<Option<CredentialsRecord>> GetCredentialsForAccount(
        EcliptixSchemaContext ctx,
        Guid accountId)
    {
        Option<AccountSecureKeyAuthEntity> authOpt = await GetPrimaryForAccount(ctx, accountId);

        if (!authOpt.IsSome)
        {
            return Option<CredentialsRecord>.None;
        }

        AccountSecureKeyAuthEntity auth = authOpt.Value;
        return Option<CredentialsRecord>.Some(new CredentialsRecord(
            auth.SecureKey,
            auth.MaskingKey,
            auth.CredentialsVersion));
    }

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

    public static async Task<Option<CredentialsRecord>> GetCredentialsForMembership(
        EcliptixSchemaContext ctx,
        Guid membershipId)
    {
        AccountSecureKeyAuthEntity? auth = await GetCredentialsForMembershipCompiled(ctx, membershipId);
        return auth != null
            ? Option<CredentialsRecord>.Some(new CredentialsRecord(
                auth.SecureKey,
                auth.MaskingKey,
                auth.CredentialsVersion))
            : Option<CredentialsRecord>.None;
    }
}
