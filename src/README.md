# Solution layout (active)

- Shared: `src/Shared/Ecliptix.SharedKernel` (cross-cutting primitives).
- Contexts: IdentityAccess, DeviceProvisioning, SecureProtocol (adapter/wrappers over `Ecliptix.Protocol.Server` via NuGet).
- SecureProtocol libraries isolate the protocol interop (`Ecliptix.SecureProtocol.Domain`) from the host (`Ecliptix.Core`), keeping protocol code out of the host assembly.
- Legacy monolith projects (`Ecliptix.Domain`, `Ecliptix.Utilities`, etc.) were removed; code now flows through the context projects referenced by `Ecliptix.Core`.

## Transport envelope contract

- gRPC entrypoint is unified: `EventGateway` in `Ecliptix.Protobufs/Protobuf/transport/gateway.proto` with Unary/ServerStream/ClientStream/BidiStream methods. Legacy typed services (e.g., DeviceService transport surface) are removed from the host; all flows go through the gateway.
- Event types are enums in proto (`IdentityAccessEventType`, `DeviceProvisioningEventType`); clients set `metadata.event_type` and the server routes via the registry. Deprecated typed context services have been removed; only the gateway surface is active.
- Required metadata for secure contexts: `connect_id` (or `partition_key` parseable as connect_id). Dispatcher will fail fast if missing and will auto-fill `partition_key` from `connect_id`.
- Optional metadata carried through responses: `app_device_id`, `application_instance_id`, `request_id`, `idempotency_key`, `platform`, `version`, `key_exchange_context`, plus correlation/causation ids.
- Responses mirror request correlation and set `status` (`OK`/`ERR`) and `error_code`; payload is serialized by the routed handler.
- Transport RPC shapes:
  - `Unary` (EventEnvelope -> EventEnvelope).
  - `ClientStream` (stream -> unary).
  - `ServerStream` (unary -> stream).
  - `BidiStream` (stream <-> stream).
- Idempotency: required for mutating transport events. If `idempotency_key` is missing for these, the dispatcher returns `idempotency_required`; invalid format (`[A-Za-z0-9._:-]`, 1–128 chars) returns `idempotency_invalid`.
  - Metadata hardening: server rejects missing `event_type` and overly long fields (event_id/event_type/request_id/context/app_device_id/application_instance_id/platform/version/locale/tenant).

  | Context              | EventType                                  |
  |----------------------|--------------------------------------------|
  | identity_access      | IdentityAccessRegistrationInit             |
  | identity_access      | IdentityAccessRegistrationComplete         |
  | identity_access      | IdentityAccessRecoveryInit                 |
  | identity_access      | IdentityAccessRecoveryComplete             |
  | identity_access      | IdentityAccessSignInInit                   |
  | identity_access      | IdentityAccessSignInComplete               |
  | identity_access      | IdentityAccessLogout                       |
  | identity_access      | IdentityAccessLogoutAnonymous              |
  | identity_access      | IdentityAccessVerifyOtp                    |
  | identity_access      | IdentityAccessValidateMobileNumber         |
  | identity_access      | IdentityAccessCheckMobileAvailability      |
  | identity_access      | IdentityAccessRecoveryMobileVerification   |
  | identity_access      | IdentityAccessCheckProfileName             |
  | identity_access      | IdentityAccessUpsertProfile                |
  | identity_access      | IdentityAccessGetProfile                   |
  | device_provisioning  | DeviceProvisioningRegisterDevice           |
  | device_provisioning  | DeviceProvisioningSecureChannelEstablish   |
  | device_provisioning  | DeviceProvisioningSecureChannelRestore     |
  | device_provisioning  | DeviceProvisioningSecureChannelAuthEstablish |

  The corresponding proto methods are annotated with comments (`Requires idempotency_key (mutating)`).

## Proto layout (context-first)

- Common/transport primitives: `Protobuf/common`, `Protobuf/transport`.
- Contexts:
  - IdentityAccess: `Protobuf/contexts/identity_access/*` (account, membership/opaque, verification/auth).
  - DeviceProvisioning: `Protobuf/contexts/device_provisioning/*` (device models/services).
  - SecureProtocol: `Protobuf/contexts/secure_protocol/*` (key exchange/materials, protocol state).

See `src/TransportEventCatalog.md` for the canonical event list and payload types.

Example envelope (IdentityAccess RegistrationInit, unary):

```json
{
  "metadata": {
    "event_id": "9f2f9d5e2b2d40f6933e84d6c5b2bcef",
    "event_type": "IdentityAccessRegistrationInit",
    "context": "identity_access",
    "connect_id": 42,
    "partition_key": "42",
    "delivery_kind": "DELIVERY_KIND_UNARY",
    "idempotency_key": "req-123",
    "platform": "avalonia",
    "version": "1.0.0",
    "request_id": "req-123"
  },
  "payload": "..." // SecureEnvelope bytes
}
```
