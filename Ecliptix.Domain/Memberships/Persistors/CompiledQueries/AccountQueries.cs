using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Protobuf.Account;
using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class AccountQueries
{
    public static async Task<List<AccountInfo>> GetAccountsByMembershipId(
        EcliptixSchemaContext ctx,
        Guid membershipId,
        CancellationToken cancellationToken = default)
    {
        List<AccountEntity> accounts = await ctx.Accounts
            .Where(a => a.MembershipId == membershipId && !a.IsDeleted)
            .OrderByDescending(a => a.IsDefaultAccount)
            .ThenBy(a => a.AccountType)
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        return accounts.Select(a => new AccountInfo(
            a.UniqueId,
            a.MembershipId,
            a.AccountType,
            a.AccountName,
            a.IsDefaultAccount,
            a.Status))
        .ToList();
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Task<AccountEntity?>>
        GetDefaultAccountByMembershipIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId) =>
                ctx.Accounts
                    .Where(a => a.MembershipId == membershipId &&
                                a.IsDefaultAccount &&
                                !a.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<AccountEntity>> GetDefaultAccountByMembershipId(
        EcliptixSchemaContext ctx,
        Guid membershipId)
    {
        AccountEntity? result = await GetDefaultAccountByMembershipIdCompiled(ctx, membershipId);
        return result is not null ? Option<AccountEntity>.Some(result) : Option<AccountEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, Guid, AccountType, Task<AccountEntity?>>
        GetAccountByMembershipIdAndTypeCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId, AccountType accountType) =>
                ctx.Accounts
                    .Where(a => a.MembershipId == membershipId &&
                                a.AccountType == accountType &&
                                !a.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<AccountEntity>> GetAccountByMembershipIdAndType(
        EcliptixSchemaContext ctx,
        Guid membershipId,
        AccountType accountType)
    {
        AccountEntity? result = await GetAccountByMembershipIdAndTypeCompiled(ctx, membershipId, accountType);
        return result is not null ? Option<AccountEntity>.Some(result) : Option<AccountEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Task<AccountEntity?>>
        GetAccountByIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid accountId) =>
                ctx.Accounts
                    .Where(a => a.UniqueId == accountId && !a.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<AccountEntity>> GetAccountById(
        EcliptixSchemaContext ctx,
        Guid accountId)
    {
        AccountEntity? result = await GetAccountByIdCompiled(ctx, accountId);
        return result is not null ? Option<AccountEntity>.Some(result) : Option<AccountEntity>.None;
    }

    public static readonly Func<EcliptixSchemaContext, Guid, Task<int>>
        CountAccountsByMembershipId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId) =>
                ctx.Accounts
                    .Where(a => a.MembershipId == membershipId && !a.IsDeleted)
                    .AsNoTracking()
                    .Count());
}
