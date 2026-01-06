# Protobuf layout (context-first)

- Common primitives: `Protobuf/common/*` (secure envelope, health).
- Transport contracts: `Protobuf/transport/*` (envelope metadata + unified gateway surface). `gateway.proto` exposes Unary/ServerStream/ClientStream/BidiStream on `EventGateway`. Legacy typed device RPCs are removed; DeviceProvisioning flows are routed via the gateway using `DeviceProvisioningEventType` names.
- Contexts:
  - IdentityAccess: `Protobuf/contexts/identity_access/*` (account, membership/opaque, verification/auth).
  - DeviceProvisioning: `Protobuf/contexts/device_provisioning/*` (device models/services).
  - SecureProtocol: `Protobuf/contexts/secure_protocol/*` (key exchange/materials, protocol state).

## Idempotency and delivery

- Mutating transport RPCs require `metadata.idempotency_key`; server rejects missing or invalid keys (`[A-Za-z0-9._:-]`, 1–128 chars) with `idempotency_required`/`idempotency_invalid`.
- `metadata.delivery_kind` should match the RPC shape: `DELIVERY_KIND_UNARY`, `CLIENT_STREAM`, `SERVER_STREAM`, `BIDI_STREAM`.

## Client guidance

- Always set `metadata.event_type`, `context`, and `connect_id` (or `partition_key` parseable as `connect_id`) for secure flows.
- Preserve `event_id` for correlation; the server echoes it as `correlation_id` unless overridden.
- Use proto enums for event types (`IdentityAccessEventType`, `DeviceProvisioningEventType`) to avoid string mismatches.
