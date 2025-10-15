using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Protobuf.Account;

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

    public static readonly Func<EcliptixSchemaContext, Guid, Task<AccountEntity?>>
        GetDefaultAccountByMembershipId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId) =>
                ctx.Accounts
                    .Where(a => a.MembershipId == membershipId &&
                                a.IsDefaultAccount &&
                                !a.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, AccountType, Task<AccountEntity?>>
        GetAccountByMembershipIdAndType = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId, AccountType accountType) =>
                ctx.Accounts
                    .Where(a => a.MembershipId == membershipId &&
                                a.AccountType == accountType &&
                                !a.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<AccountEntity?>>
        GetAccountById = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid accountId) =>
                ctx.Accounts
                    .Where(a => a.UniqueId == accountId && !a.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, Task<int>>
        CountAccountsByMembershipId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid membershipId) =>
                ctx.Accounts
                    .Where(a => a.MembershipId == membershipId && !a.IsDeleted)
                    .AsNoTracking()
                    .Count());
}
