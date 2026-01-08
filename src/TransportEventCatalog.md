# Event Gateway Event Catalog (server-side)

Server exposes only `EventGateway` (see `Protobuf/transport/gateway.proto`). Clients must set `metadata.event_type`, `metadata.context`, `metadata.delivery_kind`, and the payload described below.

## Common metadata
- `context`: `EVENT_CONTEXT_IDENTITY_ACCESS` or `EVENT_CONTEXT_DEVICE_PROVISIONING`
- `event_type`: `TransportEventType` enum values (C# enum names shown below; JSON uses proto names like `IDENTITY_ACCESS_REGISTRATION_INIT`)
- `delivery_kind`: typically `DELIVERY_KIND_UNARY`
- `connect_id` (or `partition_key` parsable as connect_id) required for secure flows
- `idempotency_key`: required for mutating operations

## IdentityAccess (payload: `Ecliptix.Protobuf.Common.SecureEnvelope`)
- `IdentityAccessRegistrationInit` (idempotency required)
- `IdentityAccessRegistrationComplete` (idempotency required)
- `IdentityAccessRecoveryInit` (idempotency required)
- `IdentityAccessRecoveryComplete` (idempotency required)
- `IdentityAccessSignInInit` (idempotency required)
- `IdentityAccessSignInComplete` (idempotency required)
- `IdentityAccessLogout` (idempotency required)
- `IdentityAccessLogoutAnonymous` (idempotency required)
- `IdentityAccessVerifyOtp`
- `IdentityAccessValidateMobileNumber`
- `IdentityAccessCheckMobileAvailability`
- `IdentityAccessRecoveryMobileVerification`
- `IdentityAccessCheckProfileName` (idempotency required)
- `IdentityAccessUpsertProfile` (idempotency required)
- `IdentityAccessGetProfile`

## DeviceProvisioning
- `DeviceProvisioningRegisterDevice` — payload: `SecureEnvelope` (idempotency required)
- `DeviceProvisioningSecureChannelEstablish` — payload: `SecureEnvelope` (idempotency required)
- `DeviceProvisioningSecureChannelRestore` — payload: `RestoreChannelRequest` (response: `RestoreChannelResponse`, idempotency required). Request is empty; connect_id supplied via metadata.
- `DeviceProvisioningSecureChannelAuthEstablish` — payload: `AuthenticatedEstablishRequest` (response: `SecureEnvelope`, idempotency required)

## Example request (unary)
```json
{
  "metadata": {
    "event_type": "DEVICE_PROVISIONING_REGISTER_DEVICE",
    "context": "EVENT_CONTEXT_DEVICE_PROVISIONING",
    "delivery_kind": "DELIVERY_KIND_UNARY",
    "connect_id": 42,
    "idempotency_key": "req-123"
  },
  "payload": "..." // protobuf-serialized payload for the event
}
```
