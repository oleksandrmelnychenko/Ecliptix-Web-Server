using Ecliptix.Protobuf.Transport.Identity;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;

/// <summary>
/// Placeholder route provider for IdentityAccess events. Extend by registering event types and handlers.
/// </summary>
public sealed class IdentityAccessEventRouteProvider : ProtobufEventRouteProvider
{
    public IdentityAccessEventRouteProvider(IServiceProvider services) : base(services)
    {
        // Membership flows
        Register(IdentityAccessEventType.IdentityAccessRegistrationInit.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessRegistrationComplete.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessRecoveryInit.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessRecoveryComplete.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessSignInInit.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessSignInComplete.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessLogout.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessLogoutAnonymous.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessGetMasterKeyShares.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);

        // Verification flows
        Register(IdentityAccessEventType.IdentityAccessVerifyOtp.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessValidateMobileNumber.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessCheckMobileAvailability.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(IdentityAccessEventType.IdentityAccessRecoveryMobileVerification.ToString(), "identity_access", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
    }
}
