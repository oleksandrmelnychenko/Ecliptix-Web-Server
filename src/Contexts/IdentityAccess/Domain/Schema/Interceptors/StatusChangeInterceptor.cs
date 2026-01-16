using System.Globalization;
using System.Text;
using System.Text.Json;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Auditing;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Ecliptix.IdentityAccess.Domain.Schema.Interceptors;

public sealed class StatusChangeInterceptor : SaveChangesInterceptor
{
    private static readonly IReadOnlyDictionary<Type, string[]> TrackedProperties = new Dictionary<Type, string[]>
    {
        {
            typeof(MembershipEntity),
            [nameof(MembershipEntity.Status), nameof(MembershipEntity.CreationStatus)]
        },
        {
            typeof(AccountEntity),
            [
                nameof(AccountEntity.Status),
                nameof(AccountEntity.IsDefaultAccount),
                nameof(AccountEntity.LastAccessedAt)
            ]
        },
        {
            typeof(VerificationFlowEntity),
            [
                nameof(VerificationFlowEntity.Status),
                nameof(VerificationFlowEntity.Purpose),
                nameof(VerificationFlowEntity.OtpCount),
                nameof(VerificationFlowEntity.LastOtpSentAt),
                nameof(VerificationFlowEntity.ResendAvailableAt),
                nameof(VerificationFlowEntity.ExpiresAt),
                nameof(VerificationFlowEntity.ConnectionId)
            ]
        },
        {
            typeof(OtpCodeEntity),
            [
                nameof(OtpCodeEntity.Status),
                nameof(OtpCodeEntity.AttemptCount),
                nameof(OtpCodeEntity.VerifiedAt),
                nameof(OtpCodeEntity.ExpiresAt)
            ]
        },
        {
            typeof(DeviceContextEntity),
            [
                nameof(DeviceContextEntity.IsActive),
                nameof(DeviceContextEntity.ActiveAccountId),
                nameof(DeviceContextEntity.ContextExpiresAt),
                nameof(DeviceContextEntity.LastActivityAt)
            ]
        },
        {
            typeof(AccountSecureKeyAuthEntity),
            [
                nameof(AccountSecureKeyAuthEntity.IsEnabled),
                nameof(AccountSecureKeyAuthEntity.IsPrimary),
                nameof(AccountSecureKeyAuthEntity.FailedAttempts),
                nameof(AccountSecureKeyAuthEntity.LockedUntil),
                nameof(AccountSecureKeyAuthEntity.ExpiresAt)
            ]
        },
        {
            typeof(AccountPinAuthEntity),
            [
                nameof(AccountPinAuthEntity.IsEnabled),
                nameof(AccountPinAuthEntity.IsPrimary),
                nameof(AccountPinAuthEntity.FailedAttempts),
                nameof(AccountPinAuthEntity.LockedUntil)
            ]
        }
    };

    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result)
    {
        AppendStatusChanges(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        AppendStatusChanges(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    private static void AppendStatusChanges(DbContext? context)
    {
        if (context == null)
        {
            return;
        }

        List<StatusChangeEntity> changes = [];
        StatusChangeContext? changeContext = StatusChangeContextAccessor.Context;
        string? serializedMetadata = SerializeMetadata(changeContext?.Metadata);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        foreach (EntityEntry entry in context.ChangeTracker.Entries())
        {
            if (entry.State != EntityState.Modified)
            {
                continue;
            }

            if (entry.Entity is StatusChangeEntity)
            {
                continue;
            }

            if (entry.Entity is not EntityBase entity)
            {
                continue;
            }

            if (entity.UniqueId == Guid.Empty)
            {
                continue;
            }

            Type entityType = entry.Entity.GetType();
            if (!TrackedProperties.TryGetValue(entityType, out string[]? properties))
            {
                continue;
            }

            foreach (string propertyName in properties)
            {
                PropertyEntry? propertyEntry = TryGetPropertyEntry(entry, propertyName);
                if (propertyEntry == null || !propertyEntry.IsModified)
                {
                    continue;
                }

                object? originalValue = propertyEntry.OriginalValue;
                object? currentValue = propertyEntry.CurrentValue;

                if (Equals(originalValue, currentValue))
                {
                    continue;
                }

                string? fromValue = FormatValue(originalValue);
                string? toValue = FormatValue(currentValue);

                changes.Add(new StatusChangeEntity
                {
                    EntityType = entry.Metadata.GetTableName() ?? entityType.Name,
                    EntityId = entity.UniqueId,
                    PropertyName = propertyName,
                    FromValue = fromValue,
                    ToValue = toValue,
                    ChangedAt = now,
                    MembershipId = changeContext?.MembershipId,
                    AccountId = changeContext?.AccountId,
                    DeviceId = changeContext?.DeviceId,
                    Source = changeContext?.Source,
                    Reason = changeContext?.Reason,
                    CorrelationId = changeContext?.CorrelationId,
                    Metadata = serializedMetadata
                });
            }
        }

        if (changes.Count == 0)
        {
            return;
        }

        context.Set<StatusChangeEntity>().AddRange(changes);
    }

    private static PropertyEntry? TryGetPropertyEntry(EntityEntry entry, string propertyName)
    {
        return entry.Metadata.FindProperty(propertyName) == null ? null : entry.Property(propertyName);
    }

    private static string? FormatValue(object? value)
    {
        if (value == null)
        {
            return null;
        }

        if (value is Enum enumValue)
        {
            return ToSnakeCase(enumValue.ToString());
        }

        if (value is DateTimeOffset dateTimeOffset)
        {
            return dateTimeOffset.ToString("O", CultureInfo.InvariantCulture);
        }

        if (value is DateTime dateTime)
        {
            return dateTime.ToString("O", CultureInfo.InvariantCulture);
        }

        if (value is bool boolValue)
        {
            return boolValue ? "true" : "false";
        }

        return value.ToString();
    }

    private static string ToSnakeCase(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        StringBuilder result = new();
        result.Append(char.ToLowerInvariant(value[0]));

        for (int i = 1; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsUpper(c))
            {
                result.Append('_');
                result.Append(char.ToLowerInvariant(c));
            }
            else
            {
                result.Append(c);
            }
        }

        return result.ToString();
    }

    private static string? SerializeMetadata(IReadOnlyDictionary<string, string>? metadata)
    {
        if (metadata == null || metadata.Count == 0)
        {
            return null;
        }

        return JsonSerializer.Serialize(metadata);
    }
}
