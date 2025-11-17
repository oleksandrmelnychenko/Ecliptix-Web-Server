using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Utilities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Memberships.Persistors.CompiledQueries;

public static class UserQueries
{

    private static readonly Func<EcliptixSchemaContext, Guid, Task<UserEntity?>>
        GetByAccountIdCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid accountId) =>
                ctx.Users
                    .Where(u => u.AccountId == accountId && !u.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<UserEntity>> GetByAccountId(
        EcliptixSchemaContext ctx,
        Guid accountId)
    {
        UserEntity? result = await GetByAccountIdCompiled(ctx, accountId);
        return result is not null ? Option<UserEntity>.Some(result) : Option<UserEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, string, Task<UserEntity?>>
        GetByUserNameCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string userName) =>
                ctx.Users
                    .Where(u => u.UserName == userName && !u.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<UserEntity>> GetByUserName(
        EcliptixSchemaContext ctx,
        string userName)
    {
        UserEntity? result = await GetByUserNameCompiled(ctx, userName);
        return result is not null ? Option<UserEntity>.Some(result) : Option<UserEntity>.None;
    }

    private static readonly Func<EcliptixSchemaContext, string, Task<UserEntity?>>
        GetPrimaryUserByMobileNumberCompiled = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, string mobileNumber) =>
                ctx.Users
                    .Where(u => u.Account.Membership.MobileNumber.Number == mobileNumber &&
                                !u.IsDeleted &&
                                !u.Account.IsDeleted &&
                                !u.Account.Membership.IsDeleted &&
                                !u.Account.Membership.MobileNumber.IsDeleted)
                    .OrderByDescending(u => u.Account.IsDefaultAccount)
                    .ThenBy(u => u.Account.AccountType)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static async Task<Option<UserEntity>> GetPrimaryUserByMobileNumber(
        EcliptixSchemaContext ctx,
        string mobileNumber)
    {
        UserEntity? result = await GetPrimaryUserByMobileNumberCompiled(ctx, mobileNumber);
        return result is not null ? Option<UserEntity>.Some(result) : Option<UserEntity>.None;
    }
}
