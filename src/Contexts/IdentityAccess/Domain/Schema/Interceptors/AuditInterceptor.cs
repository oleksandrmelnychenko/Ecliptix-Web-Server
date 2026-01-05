using Ecliptix.IdentityAccess.Domain.Schema.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Ecliptix.IdentityAccess.Domain.Schema.Interceptors;

public sealed class AuditInterceptor : SaveChangesInterceptor
{
    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result)
    {
        ApplyAuditInformation(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        ApplyAuditInformation(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    private static void ApplyAuditInformation(DbContext? context)
    {
        if (context == null)
        {
            return;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;

        foreach (EntityEntry entry in context.ChangeTracker.Entries())
        {
            if (entry.Entity is not IAuditable auditable)
            {
                continue;
            }

            switch (entry.State)
            {
                case EntityState.Added:
                    auditable.CreatedAt = now;
                    auditable.UpdatedAt = now;
                    auditable.IsDeleted = false;
                    break;

                case EntityState.Modified:
                    auditable.UpdatedAt = now;
                    break;

                case EntityState.Deleted:

                    entry.State = EntityState.Modified;
                    auditable.IsDeleted = true;
                    auditable.UpdatedAt = now;
                    break;
            }
        }
    }
}
