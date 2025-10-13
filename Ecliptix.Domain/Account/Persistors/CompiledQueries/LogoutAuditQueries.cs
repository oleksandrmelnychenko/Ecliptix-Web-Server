using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;

namespace Ecliptix.Domain.Account.Persistors.CompiledQueries;

public static class LogoutAuditQueries
{
    public static readonly Func<EcliptixSchemaContext, Guid, Task<LogoutAuditEntity?>>
        GetMostRecentByAccount = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid accountUniqueId) =>
                ctx.LogoutAudits
                    .Where(l => l.AccountUniqueId == accountUniqueId &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.LoggedOutAt)
                    .AsNoTracking()
                    .FirstOrDefault());

    public static readonly Func<EcliptixSchemaContext, Guid, int, Task<List<LogoutAuditEntity>>>
        GetLogoutHistory = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, Guid accountUniqueId, int limit) =>
                ctx.LogoutAudits
                    .Where(l => l.AccountUniqueId == accountUniqueId &&
                                !l.IsDeleted)
                    .OrderByDescending(l => l.LoggedOutAt)
                    .Take(limit)
                    .AsNoTracking()
                    .ToList());

    public static readonly Func<EcliptixSchemaContext, uint, Task<LogoutAuditEntity?>>
        GetByConnectId = EF.CompileAsyncQuery(
            (EcliptixSchemaContext ctx, uint connectId) =>
                ctx.LogoutAudits
                    .Where(l => l.ConnectId == connectId &&
                                !l.IsDeleted)
                    .AsNoTracking()
                    .FirstOrDefault());
}
