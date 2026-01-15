namespace Ecliptix.IdentityAccess.Domain.Actors;

/// <summary>
/// Capacity limits and timeout constants for the membership actor's pending operation queues.
/// </summary>
public static class MembershipActorLimits
{
    public static class QueueCapacity
    {
        /// <summary>Maximum number of pending sign-in operations.</summary>
        public const int MaxPendingSignIns = 1000;

        /// <summary>Maximum number of pending masking key operations.</summary>
        public const int MaxPendingMaskingKeys = 1000;

        /// <summary>Maximum number of pending session key operations.</summary>
        public const int MaxPendingSessionKeys = 1000;

        /// <summary>Maximum number of pending recovery timestamp entries.</summary>
        public const int MaxPendingRecoveryTimestamps = 1000;
    }

    public static class PasswordRecovery
    {
        /// <summary>Default timeout for pending password recovery operations.</summary>
        public static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(15);
    }

    public static class Opaque
    {
        /// <summary>Required length for OPAQUE account identifier in bytes (GUID size).</summary>
        public const int AccountIdLength = 16;

        /// <summary>Required length for OPAQUE masking key in bytes.</summary>
        public const int MaskingKeyLength = 32;
    }
}
