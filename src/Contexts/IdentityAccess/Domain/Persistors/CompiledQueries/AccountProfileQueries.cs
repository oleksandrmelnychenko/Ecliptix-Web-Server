using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;

public static class AccountProfileQueries
{

    private static readonly Func<EcliptixSchemaContext, Guid, Task<AccountProfileEntity?>>
        GetByAccountIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid accountId) =>
                ctx.AccountProfiles
                    .Where(p => p.AccountId == accountId && !p.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<AccountProfileEntity>> GetByAccountId(
        EcliptixSchemaContext ctx,
        Guid accountId)
    {
        AccountProfileEntity? result = await GetByAccountIdCompiled(ctx, accountId);
        return result is not null ? Option<AccountProfileEntity>.Some(result) : Option<AccountProfileEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, string, Task<AccountProfileEntity?>>
        GetByProfileNameCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string profileName) =>
                ctx.AccountProfiles
                    .Where(p => p.ProfileName == profileName && !p.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<AccountProfileEntity>> GetByProfileName(
        EcliptixSchemaContext ctx,
        string profileName)
    {
        AccountProfileEntity? result = await GetByProfileNameCompiled(ctx, profileName);
        return result is not null ? Option<AccountProfileEntity>.Some(result) : Option<AccountProfileEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, string, Guid, Task<AccountProfileEntity?>>
        GetPrimaryAccountProfileByMobileNumberCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber, Guid currentAccountId) =>
                ctx.AccountProfiles
                    .Where(p => p.Account.Membership.MobileNumber.Number == mobileNumber &&
                                p.AccountId != currentAccountId &&
                                !p.IsDeleted &&
                                !p.Account.IsDeleted &&
                                !p.Account.Membership.IsDeleted &&
                                !p.Account.Membership.MobileNumber.IsDeleted)
                    .OrderByDescending(p => p.Account.IsDefaultAccount)
                    .ThenBy(p => p.Account.AccountType)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<AccountProfileEntity>> GetPrimaryAccountProfileByMobileNumber(
        EcliptixSchemaContext ctx,
        string mobileNumber,
        Guid currentAccountId)
    {
        AccountProfileEntity? result = await GetPrimaryAccountProfileByMobileNumberCompiled(
            ctx, mobileNumber, currentAccountId);
        return result is not null ? Option<AccountProfileEntity>.Some(result) : Option<AccountProfileEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Task<AccountProfileEntity?>>
        GetByAccountIdTrackingCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid accountId) =>
                ctx.AccountProfiles
                    .FirstOrDefault(p => p.AccountId == accountId && !p.IsDeleted));

    public static async Task<Option<AccountProfileEntity>> GetByAccountIdTracking(
        EcliptixSchemaContext ctx, Guid accountId)
    {
        AccountProfileEntity? result = await GetByAccountIdTrackingCompiled(ctx, accountId);
        return result is not null ? Option<AccountProfileEntity>.Some(result) : Option<AccountProfileEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, string, Task<bool>>
        IsProfileNameTakenCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string profileName) =>
                ctx.AccountProfiles.Any(p => p.ProfileName == profileName && !p.IsDeleted));

    public static Task<bool> IsProfileNameTaken(EcliptixSchemaContext ctx, string profileName)
    {
        return IsProfileNameTakenCompiled(ctx, profileName);
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Task<Guid?>>
        GetMembershipIdByAccountIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid accountId) =>
                ctx.Accounts
                    .Where(a => a.UniqueId == accountId && !a.IsDeleted)
                    .Select(a => (Guid?)a.MembershipId)
                    .FirstOrDefault());

    public static async Task<Option<Guid>> GetMembershipIdByAccountId(
        EcliptixSchemaContext ctx,
        Guid accountId)
    {
        Guid? result = await GetMembershipIdByAccountIdCompiled(ctx, accountId);
        return result.HasValue ? Option<Guid>.Some(result.Value) : Option<Guid>.None;
    }
}
