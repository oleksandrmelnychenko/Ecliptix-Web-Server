# CipherPayload Refactoring Plan - Signal Protocol-Inspired Design

## Current Issues
- CipherPayload mixes transport metadata with cryptographic material
- No clear separation between protocol versioning and message content
- Ratchet index needs to be accessible WITHOUT decryption (chicken-and-egg problem)

## Critical Design Constraint
**The ratchet_index MUST be plaintext** because it's needed to identify which message key to use for decryption.

## Recommended Design for Ecliptix

```protobuf
syntax = "proto3";

package ecliptix.proto.common;
option csharp_namespace = "Ecliptix.Protobuf.Common";

import "google/protobuf/timestamp.proto";

// Everything needed to bootstrap decryption - MUST BE PLAINTEXT
message CipherHeader {
  uint32 request_id = 1;
  uint32 ratchet_index = 2;          // MUST be plaintext to find decryption key
  bytes nonce = 3;                   // MUST be plaintext for decryption
  optional bytes dh_public_key = 4;  // MUST be plaintext for ratchet rotation
  uint32 protocol_version = 5;       // For compatibility
}

// The complete payload
message CipherPayload {
  CipherHeader header = 1;     // UNENCRYPTED - bootstrap info
  bytes encrypted_body = 2;    // ENCRYPTED - all other metadata + payload
  bytes auth_tag = 3;          // HMAC/Poly1305 over header + encrypted_body
}

// What's inside encrypted_body after decryption
message DecryptedBody {
  uint32 connect_id = 1;
  uint32 message_type = 2;
  google.protobuf.Timestamp created_at = 3;
  bytes actual_payload = 4;    // The real protobuf message
}
```

## How This Works

### Encryption Flow:
1. Create DecryptedBody with metadata + actual payload
2. Serialize DecryptedBody to bytes
3. Use ratchet_index to get correct MessageKey from chain
4. Encrypt(MessageKey, nonce, serialized DecryptedBody) → encrypted_body
5. Create CipherHeader with ratchet_index, nonce, DH key
6. Compute auth_tag over (header + encrypted_body)
7. Assemble final CipherPayload

### Decryption Flow:
1. Read CipherHeader.ratchet_index (NO DECRYPTION NEEDED!)
2. Use ratchet_index to retrieve correct MessageKey from Double Ratchet chain
3. Verify auth_tag over (header + encrypted_body)
4. Decrypt encrypted_body using MessageKey and nonce
5. Parse DecryptedBody to get metadata and actual payload

## Implementation Changes Required

### 1. Update Protocol Layer (EcliptixProtocolSystem.cs)
- Modify `ProduceSingleMessage` (line 567-577) to use new structure
- Update `ProcessSingleInboundMessage` to handle new format
- Add auth_tag generation/verification for AEAD

### 2. Update gRPC Services
- Modify `GrpcCipherService` to work with new structure
- Update all service bases to handle new metadata

### 3. Update Actor System
- `EcliptixProtocolConnectActor` to use new message format
- Update persistence to handle new structure

### 4. Add Migration Support
- Support both old and new formats during transition
- Use protocol_version field for compatibility

## Benefits

1. **Signal-like Architecture**
   - Clean separation of concerns
   - Metadata processable without decryption
   - Better debugging and monitoring

2. **Enhanced Security**
   - Explicit auth_tag for AEAD verification
   - Cipher suite field for algorithm agility
   - Better replay protection

3. **Solves Bootstrap Problem**
   - Ratchet index is plaintext (safe - just position in chain)
   - DH public key is plaintext (safe - it's public)
   - Nonce is plaintext (safe - random value)
   - Everything sensitive is encrypted

## Security Considerations

- **Plaintext ratchet_index**: Not a security risk - just indicates position in chain
- **Plaintext DH key**: Public key, safe to expose
- **Plaintext nonce**: Random value, safe to expose
- **Auth tag**: Ensures plaintext fields can't be tampered with

## Alternative Approach - Signal's Actual Pattern

Signal uses a two-layer approach:

```protobuf
// Outer envelope - completely unencrypted
message MessageEnvelope {
  uint32 source_device_id = 1;
  uint32 destination_device_id = 2;
  uint64 timestamp = 3;
  uint32 message_version = 4;
  bytes content = 5;  // Contains WhisperMessage
}

// Inner message - partially encrypted
message WhisperMessage {
  bytes ratchet_key = 1;      // Current ratchet public key (UNENCRYPTED)
  uint32 counter = 2;          // Message counter (UNENCRYPTED) 
  uint32 previous_counter = 3; // Previous counter (UNENCRYPTED)
  bytes ciphertext = 4;        // ENCRYPTED actual content
  // MAC is computed over all fields
}
```

## Migration Strategy
1. Add new proto definitions alongside existing
2. Update protocol to generate new format
3. Add compatibility layer to handle both formats
4. Gradually migrate all services
5. Remove old format support after full migration

## Next Steps
1. Fix current compilation issues with authentication system
2. Complete testing of authentication context implementation
3. Return to implement this CipherPayload refactoring

---
*This design follows Signal's principle: "Only expose what's absolutely necessary for decryption bootstrap, encrypt everything else."*