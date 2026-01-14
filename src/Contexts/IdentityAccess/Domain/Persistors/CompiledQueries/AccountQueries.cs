using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;

public static class AccountQueries
{

    public static async Task<List<AccountInfo>> GetAccountsByMembershipId(
        EcliptixSchemaContext schemaContext,
        Guid membershipId,
        CancellationToken cancellationToken = default)
    {
        return await schemaContext.Accounts
            .AsNoTracking()
            .Where(a => a.MembershipId == membershipId && !a.IsDeleted)
            .OrderByDescending(a => a.IsDefaultAccount)
            .ThenBy(a => a.AccountType)
            .Select(a => new AccountInfo(
                a.UniqueId,
                a.MembershipId,
                a.AccountType,
                a.IsDefaultAccount,
                a.Status))
            .ToListAsync(cancellationToken);
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Task<AccountEntity?>>
        GetDefaultAccountByMembershipIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext schemaContext, Guid membershipId) =>
                schemaContext.Accounts
                    .AsNoTracking()
                    .FirstOrDefault(a => a.MembershipId == membershipId &&
                                        a.IsDefaultAccount &&
                                        !a.IsDeleted));

    public static async Task<Option<AccountEntity>> GetDefaultAccountByMembershipId(
        EcliptixSchemaContext schemaContext,
        Guid membershipId)
    {
        AccountEntity? result = await GetDefaultAccountByMembershipIdCompiled(schemaContext, membershipId);
        return result is not null ? Option<AccountEntity>.Some(result) : Option<AccountEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, Guid, Task<AccountEntity?>>
        GetAccountByIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext schemaContext, Guid accountId) =>
                schemaContext.Accounts
                    .AsNoTracking()
                    .FirstOrDefault(a => a.UniqueId == accountId && !a.IsDeleted));

    public static async Task<Option<AccountEntity>> GetAccountById(
        EcliptixSchemaContext schemaContext,
        Guid accountId)
    {
        AccountEntity? result = await GetAccountByIdCompiled(schemaContext, accountId);
        return result is not null ? Option<AccountEntity>.Some(result) : Option<AccountEntity>.None;
    }
}
